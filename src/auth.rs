//! 登录 / 继续授权 / 登出处理器
//!
//! 实现用户名密码登录（含进才外部验证、管理员本地验证、账户状态检查）
//! 与 OAuth 授权码签发。

use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};
use uuid::Uuid;

use crate::db;
use crate::models::{AuthSession, SessionData, UserFlag, UserState};
use crate::state::AppState;
use crate::utils::{
    create_sso_cookie, decrypt_frontend_payload, extract_client_ip, redirect_matches,
};
use crate::zline;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub encrypted_payload: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub remember: Option<bool>,
    pub sync_info: Option<bool>,
}

pub async fn logout_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 如果有session cookie，从session_store中删除
    if let Some(session_cookie) = jar.get("sso_session") {
        state
            .session_store
            .lock()
            .unwrap()
            .remove(session_cookie.value());
    }

    let query_str = serde_urlencoded::to_string(&params).unwrap_or_default();
    let auth_path = state.config.auth_path_prefix.clone();
    let remove_cookie = Cookie::build(("sso_session", ""))
        .path(auth_path.clone())
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    (
        jar.add(remove_cookie),
        Redirect::to(&format!("{}?{}", auth_path, query_str)),
    )
}

/// 检查账户限制（Restricted/Locked）是否已到期，到期则自动解除。
///
/// 返回解除后应使用的状态。
fn clear_expired_restriction(conn: &db::DbConn, user_info: &db::UserInfo, state: UserState) -> UserState {
    if (state == UserState::Restricted || state == UserState::Locked)
        && user_info.restriction_end_time.is_some()
    {
        let end = user_info.restriction_end_time.unwrap_or(0);
        if end > 0 && chrono::Utc::now().timestamp() >= end {
            // 限制已过期，解除限制
            let _ = db::set_user_state(conn, &user_info.uid, UserState::Normal, "", 0);
            return UserState::Normal;
        }
    }
    state
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // 提取客户端 IP 地址
    let client_ip = extract_client_ip(&headers, Some(socket_addr));
    let geo_location = state.lookup_geo_location(&client_ip);
    let client_id = payload.client_id.as_ref().map(|s| s.as_str()).unwrap_or("");
    let redirect_uri = payload
        .redirect_uri
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("");
    let is_direct_login = client_id.is_empty(); // 是否不带参数访问登录页面,即进入个人中心
    let mut sync_info = payload.sync_info.unwrap_or_default();
    let mut new_user_record = false;

    // 带参数，即从外部app发起验证时，验证 OAuth 参数
    if !is_direct_login {
        let client = state
            .config
            .clients
            .iter()
            .find(|c| c.client_id == client_id);
        if client.is_none() {
            return Json(json!({"error": "OAuth客户端ID错误"})).into_response();
        }
        // redirect_uri 校验：字面量精确匹配，或按配置的正则表达式匹配
        let redirect_ok = client
            .unwrap()
            .redirect_uris
            .iter()
            .any(|pattern| redirect_matches(pattern, redirect_uri));
        if !redirect_ok {
            return Json(json!({"error": "OAuth重定向URI错误"})).into_response();
        }
    }

    // 从表单中解密返回的明文username和password
    let enc_payload = match &payload.encrypted_payload {
        Some(p) => p,
        None => return Json(json!({"error": "缺少加密负载"})).into_response(),
    };
    let (user, pass) = match decrypt_frontend_payload(
        enc_payload,
        &state.config.frontend_crypto.shared_key,
        state.config.frontend_crypto.max_clock_skew_secs,
    ) {
        Ok(data) => data,
        Err(e) => return Json(json!({"error": e})).into_response(),
    };
    // 记住登录状态的选项
    let remember = payload.remember.unwrap_or(false);

    // 管理员账户本地预检：在发往外部（进才）验证之前先校验，
    // 命中管理员账户则直接完成登录，避免管理员凭据泄漏到进才系统。
    if state.is_admin(&user, &pass) {
        // 管理员账户仅允许用户中心（直接）登录，不允许 OAuth 授权
        if !is_direct_login {
            return Json(
                json!({"error": "管理员账户不允许OAuth授权，请在用户中心直接登录"}),
            )
            .into_response();
        }

        // 管理员直接登录用户中心（adminui）
        let session_id = Uuid::new_v4().to_string();
        state.session_store.lock().unwrap().insert(
            session_id.clone(),
            SessionData {
                username: user.clone(),
                is_admin: true,
                created_at: SystemTime::now(),
            },
        );

        let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
        info!(username = %user, ip = %client_ip, "管理员登录成功");
        return (
            jar.add(create_sso_cookie(&state, session_id, remember)),
            Json(json!({
                "code": "profile",
                "redirect_uri": redirect_uri,
                "is_direct_login": true
            })),
        )
            .into_response();
    }

    let db_conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    // 查询用户本地信息（一次查询获取所有字段）
    let user = user.to_string();
    let user_info = match db::get_user_full_info(&db_conn, &user) {
        Ok(Some(info)) => info,
        Ok(None) => {
            new_user_record = true;
            if let Err(_) = db::upsert_user(&db_conn, &user, "", "", "", "") {
                return Json(json!({"error": "内部错误"})).into_response();
            }
            match db::get_user_full_info(&db_conn, &user) {
                Ok(Some(info)) => info,
                _ => return Json(json!({"error": "内部错误"})).into_response(),
            }
        }
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };
    let (user_state, user_flag): (UserState, UserFlag) = (
        user_info.state.try_into().unwrap_or_default(),
        user_info.flag.try_into().unwrap_or_default(),
    );
    if user_flag == UserFlag::Uninitialized {
        // 如果是未初始化状态，强制同步信息（可能是新用户第一次登录）
        sync_info = true;
    }
    // 检查限制是否已到期，到期自动解除
    let user_state = clear_expired_restriction(&db_conn, &user_info, user_state);

    match user_state {
        UserState::Normal => {
            // 执行进才验证
            match zline::login_with_jincai(&state.http_client, user.clone(), pass.to_string()).await
            {
                Ok(external_cookie) => {
                    if sync_info {
                        // 获取外部用户信息
                        let (xuid, xuxm, student_id, gender) =
                            zline::get_external_user_info(&state.http_client, &external_cookie)
                                .await
                                .unwrap_or_default();
                        // 仅在取得非空数据时才覆盖本地信息，避免清空已有资料
                        if !xuid.is_empty() || !xuxm.is_empty() {
                            db::set_user_flag(&db_conn, &user_info.uid, UserFlag::Normal).ok();
                            db::upsert_user(&db_conn, &user, &xuid, &xuxm, &student_id, &gender)
                                .ok();
                        }
                    }
                    db::record_login_success(
                        &db_conn,
                        &user_info.uid,
                        &client_ip,
                        &geo_location.country,
                        &geo_location.region,
                    )
                    .ok();

                    info!(
                        username = %user,
                        client_id = %client_id,
                        ip = %client_ip,
                        "登录成功"
                    );

                    // 生成session ID并存储用户信息
                    let session_id = Uuid::new_v4().to_string();
                    state.session_store.lock().unwrap().insert(
                        session_id.clone(),
                        SessionData {
                            username: user.clone(),
                            is_admin: false,
                            created_at: SystemTime::now(),
                        },
                    );

                    // 验证成功，生成登录响应
                    return (
                        jar.add(create_sso_cookie(&state, session_id, remember)),
                        handle_login_response(
                            &state,
                            user,
                            client_id.to_string(),
                            redirect_uri.to_string(),
                            payload.state,
                            payload.nonce,
                            is_direct_login,
                        ),
                    )
                        .into_response();
                }
                Err(e) => {
                    if new_user_record {
                        db::upsert_user(&db_conn, &user, "", "", "", "").ok();
                    }
                    // 记录登录失败
                    db::record_login_failure(
                        &db_conn,
                        &user_info.uid,
                        &client_ip,
                        &geo_location.country,
                        &geo_location.region,
                    )
                    .ok();

                    warn!(
                        username = %user,
                        ip = %client_ip,
                        failed_attempts = user_info.failed_attempts + 1,
                        "登录失败"
                    );

                    // 检查是否应该锁定账户
                    if user_info.failed_attempts + 1
                        >= state.config.account_lockout.failed_attempts_threshold
                    {
                        // 计算锁定结束时间（Unix 时间戳，秒）
                        let lockout_end = chrono::Utc::now().timestamp()
                            + (state.config.account_lockout.lockout_duration_minutes as i64) * 60;
                        let _ = db::set_user_state(
                            &db_conn,
                            &user_info.uid,
                            UserState::Locked,
                            &format!(
                                "账户由于登录失败 {} 次已被锁定，将在 {} 自动解封",
                                user_info.failed_attempts + 1,
                                format_local_time(lockout_end)
                            ),
                            lockout_end,
                        );
                    }

                    return Json(json!({"error": e.to_string()})).into_response();
                }
            }
        }
        UserState::Restricted => {
            if is_direct_login {
                // 执行进才验证
                match zline::login_with_jincai(&state.http_client, user.clone(), pass.to_string())
                    .await
                {
                    Ok(external_cookie) => {
                        if sync_info {
                            // 获取外部用户信息
                            let (xuid, xuxm, student_id, gender) =
                                zline::get_external_user_info(&state.http_client, &external_cookie)
                                    .await
                                    .unwrap_or_default();
                            // 仅在取得非空数据时才覆盖本地信息，避免清空已有资料
                            if !xuid.is_empty() || !xuxm.is_empty() {
                                let _ = db::upsert_user(
                                    &db_conn,
                                    &user,
                                    &xuid,
                                    &xuxm,
                                    &student_id,
                                    &gender,
                                );
                            }
                        }
                        db::record_login_success(
                            &db_conn,
                            &user_info.uid,
                            &client_ip,
                            &geo_location.country,
                            &geo_location.region,
                        )
                        .ok();

                        // 生成session ID并存储
                        let session_id = Uuid::new_v4().to_string();
                        state.session_store.lock().unwrap().insert(
                            session_id.clone(),
                            SessionData {
                                username: user.clone(),
                                is_admin: false,
                                created_at: SystemTime::now(),
                            },
                        );

                        // 允许进入个人中心
                        let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
                        return (
                            jar.add(create_sso_cookie(&state, session_id, remember)),
                            Json(json!({
                                "code": "profile",
                                "redirect_uri": redirect_uri,
                                "is_direct_login": true
                            })),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        db::record_login_failure(
                            &db_conn,
                            &user_info.uid,
                            &client_ip,
                            &geo_location.country,
                            &geo_location.region,
                        )
                        .ok();

                        // 检查是否应该锁定账户
                        if user_info.failed_attempts + 1
                            >= state.config.account_lockout.failed_attempts_threshold
                        {
                            let lockout_end = chrono::Utc::now().timestamp()
                                + (state.config.account_lockout.lockout_duration_minutes as i64)
                                    * 60;
                            let _ = db::set_user_state(
                                &db_conn,
                                &user_info.uid,
                                UserState::Locked,
                                &format!(
                                    "账户由于登录失败 {} 次已被锁定，将在 {} 自动解封",
                                    user_info.failed_attempts + 1,
                                    format_local_time(lockout_end)
                                ),
                                lockout_end,
                            );
                        }

                        return Json(json!({"error": e.to_string()})).into_response();
                    }
                }
            } else {
                // 拒绝 OAuth 登录
                return Json(json!({"error": "账号处于限制状态,登录个人中心查看原因".to_string()}))
                    .into_response();
            }
        }
        UserState::Locked => {
            return Json(json!({"error": "账号处于锁定状态,请直接联系您的管理员。附加信息：".to_string() + &user_info.state_description.unwrap_or_else(|| "无".to_string())}))
                .into_response();
        }
        UserState::BypassExternal => {
            // 跳过外部验证，直接登录
            let session_id = Uuid::new_v4().to_string();
            state.session_store.lock().unwrap().insert(
                session_id.clone(),
                SessionData {
                    username: user.clone(),
                    is_admin: false,
                    created_at: SystemTime::now(),
                },
            );
            return (
                jar.add(create_sso_cookie(&state, session_id, remember)),
                handle_login_response(
                    &state,
                    user,
                    client_id.to_string(),
                    redirect_uri.to_string(),
                    payload.state,
                    payload.nonce,
                    is_direct_login,
                ),
            )
                .into_response();
        }
    }
}

pub async fn continue_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Query(payload): Query<LoginRequest>,
) -> Response {
    // 提取客户端 IP 地址
    let _client_ip = extract_client_ip(&headers, Some(socket_addr));
    let session_id = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => return Json(json!({"error": "会话已过期"})).into_response(),
    };

    // 从session_store查询用户名及是否管理员会话
    let (user, session_is_admin) = match state.session_store.lock().unwrap().get(&session_id) {
        Some(session) => (session.username.clone(), session.is_admin),
        None => return Json(json!({"error": "会话已过期"})).into_response(),
    };

    let client_id = payload.client_id.as_ref().map(|s| s.as_str()).unwrap_or("");
    let redirect_uri = payload
        .redirect_uri
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("");
    let is_direct_login = client_id.is_empty(); // 是否不带参数访问登录页面,即进入个人中心

    if !is_direct_login {
        let client = match state.config.clients.iter().find(|c| c.client_id == client_id) {
            Some(c) => c,
            None => return Json(json!({"error": "OAuth客户端ID错误"})).into_response(),
        };
        let redirect_ok = client
            .redirect_uris
            .iter()
            .any(|pattern| redirect_matches(pattern, redirect_uri));
        if !redirect_ok {
            return Json(json!({"error": "OAuth客户端ID错误"})).into_response();
        }
    }

    // 管理员会话：仅允许用户中心（直接）登录，不允许 OAuth 授权
    if session_is_admin {
        if is_direct_login {
            let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
            return Json(json!({
                "code": "profile",
                "redirect_uri": redirect_uri,
                "is_direct_login": true
            }))
            .into_response();
        } else {
            return Json(json!({"error": "管理员账户不允许OAuth授权"})).into_response();
        }
    }

    let db_conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&db_conn, &user) {
        Ok(Some(info)) => info,
        Ok(None) => {
            db::upsert_user(&db_conn, &user, "", "", "", "").ok();
            db::get_user_full_info(&db_conn, &user).unwrap().unwrap()
        }
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_state: UserState = user_info.state.try_into().unwrap_or_default();
    // 检查限制是否已到期，到期自动解除
    let user_state = clear_expired_restriction(&db_conn, &user_info, user_state);

    match user_state {
        UserState::Normal | UserState::BypassExternal => {
            if !is_direct_login {
                handle_login_response(
                    &state,
                    user,
                    client_id.to_string(),
                    redirect_uri.to_string(),
                    payload.state,
                    payload.nonce,
                    is_direct_login,
                )
            } else {
                // 允许进入个人中心
                let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
                Json(json!({
                    "code": "profile",
                    "redirect_uri": redirect_uri,
                    "is_direct_login": true
                }))
                .into_response()
            }
        }
        UserState::Restricted => {
            if is_direct_login {
                // 允许进入个人中心
                let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
                Json(json!({
                    "code": "profile",
                    "redirect_uri": redirect_uri,
                    "is_direct_login": true
                }))
                .into_response()
            } else {
                Json(json!({"error": "账号处于限制状态,登录个人中心查看原因".to_string()}))
                    .into_response()
            }
        }
        UserState::Locked => {
            Json(
                json!({"error": "账号处于锁定状态,请直接联系您的管理员。附加信息：".to_string() + &user_info.state_description.unwrap_or_else(|| "无".to_string())}),
            )
            .into_response()
        }
    }
}

/// 将 Unix 时间戳（秒）格式化为服务器本地时间的可读字符串（用于状态描述）。
pub fn format_local_time(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// 生成登录后的HTTP响应
///
/// 根据登录类型生成不同的响应：
/// - OAuth登录：生成授权码并返回给客户端，客户端稍后用该码换取token
/// - 个人中心登录：返回特殊响应表示用户可以进入个人中心
///
/// # 返回值
/// 返回HTTP响应（JSON格式），包含：
/// - OAuth登录: `{code: "生成的授权码", redirect_uri, state}`
/// - 个人中心: `{code: "profile", redirect_uri: "/auth/profile", is_direct_login: true, state}`
pub fn handle_login_response(
    state: &Arc<AppState>,
    username: String,
    client_id: String,
    redirect_uri: String,
    oauth_state: Option<String>,
    nonce: Option<String>,
    is_direct_login: bool,
) -> Response {
    if !is_direct_login {
        // 常规登录：生成授权码，并记录其关联的 redirect_uri、nonce 与创建时间
        let code = Uuid::new_v4().to_string();
        state.code_store.lock().unwrap().insert(
            code.clone(),
            AuthSession {
                username,
                client_id,
                nonce: nonce.clone(),
                created_at: SystemTime::now(),
            },
        );

        Json(json!({
            "code": code,
            "redirect_uri": redirect_uri,
            "state": oauth_state,
            "nonce": nonce
        }))
        .into_response()
    } else {
        // 个人中心登录
        let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
        Json(json!({
            "code": "profile",
            "redirect_uri": redirect_uri,
            "state": oauth_state,
            "is_direct_login": true
        }))
        .into_response()
    }
}
