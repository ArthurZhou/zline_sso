mod db;
mod statics;
mod zline;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use axum::{
    Form, Router,
    extract::{ConnectInfo, Query, State},
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use base64::Engine;
use base64::engine::general_purpose;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use tower_governor::key_extractor::PeerIpKeyExtractor;
use maxminddb::Reader;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

#[derive(Deserialize, Clone)]
struct Config {
    host: String,
    port: u16,
    issuer: String,
    rate_limit: RateLimitConfig,
    geoip_mmdb_path: String,
    frontend_crypto: CryptoConfig,
    account_lockout: AccountLockoutConfig,
    clients: Vec<ClientConfig>,
}

#[derive(Deserialize, Clone)]
struct RateLimitConfig {
    per_second: u64,
}

#[derive(Deserialize, Clone)]
struct CryptoConfig {
    shared_key: String,
    max_clock_skew_secs: i64,
}

#[derive(Deserialize, Clone)]
struct AccountLockoutConfig {
    failed_attempts_threshold: i32,
    lockout_duration_minutes: i32,
}

#[derive(Deserialize, Clone)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
    return_extra_userinfo: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct LoginRequest {
    encrypted_payload: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    remember: Option<bool>,
    sync_info: Option<bool>,
}

#[derive(Deserialize)]
struct TokenExchangeRequest {
    code: String,
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    iat: usize,
}

struct AuthSession {
    username: String,
    client_id: String,
}

struct SessionData {
    username: String,
    #[allow(dead_code)]
    created_at: std::time::SystemTime,
}

#[derive(Debug, Clone)]
struct GeoLocation {
    country: String,
    region: String,
}

struct AppState {
    config: Config,
    http_client: reqwest::Client,
    keys: RwLock<Arc<(rsa::RsaPrivateKey, String)>>,
    code_store: Mutex<HashMap<String, AuthSession>>,
    session_store: Mutex<HashMap<String, SessionData>>,
    db_pool: db::DbPool,
    geoip_reader: Option<Arc<Reader<Vec<u8>>>>,
    geoip_cache: Mutex<HashMap<String, GeoLocation>>,
}

impl AppState {
    fn lookup_geo_location(&self, ip: &str) -> GeoLocation {
        if ip == "-1" {
            return GeoLocation {
                country: "未知".to_string(),
                region: "未知".to_string(),
            };
        }

        if let Some(location) = self.geoip_cache.lock().unwrap().get(ip) {
            return location.clone();
        }

        let location = self.resolve_geo_location(ip);
        self.geoip_cache
            .lock()
            .unwrap()
            .insert(ip.to_string(), location.clone());
        location
    }

    fn resolve_geo_location(&self, ip: &str) -> GeoLocation {
    let default_unknown = GeoLocation {
        country: "未知".to_string(),
        region: "未知".to_string(),
    };

    let lan_location = GeoLocation {
        country: "局域网".to_string(),
        region: "局域网".to_string(),
    };

    // 1. 解析 IP 字符串
    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return default_unknown,
    };

    // 2. 识别内网/私有地址
    if AppState::is_lan(ip_addr) {
        return lan_location;
    }

    // 3. 检查 Reader 是否可用
    let reader = match self.geoip_reader.as_ref() {
        Some(reader) => reader,
        None => return default_unknown,
    };

    // 4. 查询 MMDB
    let data: serde_json::Value = match reader.lookup(ip_addr) {
        Ok(d) => d,
        Err(_) => return default_unknown,
    };

    // 5. 提取国家 (优先中文)
    let country = data.get("country")
        .and_then(|c| c.get("names"))
        .or_else(|| data.get("registered_country").and_then(|rc| rc.get("names")))
        .and_then(|n| n.get("zh-CN").or(n.get("en")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "未知".to_string());

    // 6. 提取地区 (优先中文)
    let region = data.get("subdivisions")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|f| f.get("names"))
        .or_else(|| data.get("city").and_then(|c| c.get("names")))
        .and_then(|n| n.get("zh-CN").or(n.get("en")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "未知".to_string());

    GeoLocation { country, region }
}

/// 辅助函数：判断 IP 是否属于局域网或保留地址
fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || // 127.0.0.1
            v4.is_private() ||  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            v4.is_link_local()  // 169.254.0.0/16
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || // ::1
            // 检查是否为唯一本地地址 (fc00::/7) 或 链路本地地址 (fe80::/10)
            (v6.segments()[0] & 0xfe00) == 0xfc00 || 
            (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}
}

#[derive(PartialEq, Default)]
enum UserState {
    Normal = 0,
    Restricted = 1, // 账户被禁，但允许登录个人中心
    #[default]
    Locked = 2, // 账户被禁，完全禁止登录
    BypassExternal = 3, // 跳过外部验证，直接登录（用于特殊账户）
}

impl TryFrom<i32> for UserState {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            x if x == UserState::Normal as i32 => Ok(UserState::Normal),
            x if x == UserState::Restricted as i32 => Ok(UserState::Restricted),
            x if x == UserState::Locked as i32 => Ok(UserState::Locked),
            x if x == UserState::BypassExternal as i32 => Ok(UserState::BypassExternal),
            _ => Ok(UserState::Locked), // 默认其他状态为 Locked，禁止登录
        }
    }
}

/// 用户状态标记（个位数表示账户标记）
#[derive(PartialEq, Default)]
enum UserFlag {
    #[default]
    Uninitialized = 0, // 未初始化
    Normal = 1,    // 正常账户
    Deleted = 2,   // 已删除
    Suspended = 3, // 暂停
}

impl TryFrom<i32> for UserFlag {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            x if x == UserFlag::Normal as i32 => Ok(UserFlag::Normal),
            x if x == UserFlag::Uninitialized as i32 => Ok(UserFlag::Uninitialized),
            x if x == UserFlag::Deleted as i32 => Ok(UserFlag::Deleted),
            x if x == UserFlag::Suspended as i32 => Ok(UserFlag::Suspended),
            _ => Ok(UserFlag::Uninitialized),
        }
    }
}

// ============ HTTP 处理器 ============

/// 从请求头中提取客户端 IP 地址
/// 优先级：X-Forwarded-For -> X-Real-IP -> 连接地址
fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    socket_addr: Option<std::net::SocketAddr>,
) -> String {
    // 检查 X-Forwarded-For 头（nginx 转发）
    if let Some(forwarded_header) = headers.get("x-forwarded-for") {
        if let Ok(forwarded) = forwarded_header.to_str() {
            // X-Forwarded-For 可能包含多个 IP，取第一个（原始客户端 IP）
            if let Some(ip) = forwarded.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // 检查 X-Real-IP 头（某些 nginx 配置）
    if let Some(real_ip_header) = headers.get("x-real-ip") {
        if let Ok(real_ip) = real_ip_header.to_str() {
            return real_ip.to_string();
        }
    }

    // 使用直接连接地址
    socket_addr.map(|addr| addr.ip().to_string()).unwrap_or_else(|| "-1".to_string())
}

// ============ HTTP 处理器 ============

async fn logout_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // 如果有session cookie，从session_store中删除
    if let Some(session_cookie) = jar.get("sso_session") {
        state.session_store.lock().unwrap().remove(session_cookie.value());
    }

    let query_str = serde_urlencoded::to_string(&params).unwrap_or_default(); // 保存当前url
    let remove_cookie = Cookie::build(("sso_session", ""))
        .path("/auth")
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    (
        jar.add(remove_cookie),
        Redirect::to(&format!("/auth/?{}", query_str)),
    )
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // 提取客户端 IP 地址
    let client_ip = extract_client_ip(&headers, Some(socket_addr));
    let geo_location = state.lookup_geo_location(&client_ip);
    let client_id = payload.client_id.clone().unwrap_or_default();
    let redirect_uri = payload.redirect_uri.clone().unwrap_or_default();
    let is_direct_login = client_id.is_empty(); // 是否不带参数访问登录页面,即进入个人中心
    let mut sync_info = payload.sync_info.clone().unwrap_or_default();
    let mut new_user_record = false;

    // 带参数，即从外部app发起验证时，验证 OAuth 参数
    if !is_direct_login {
        let client = state.config.clients.iter().find(|c| c.client_id == client_id);
        if client.is_none() {
            return Json(json!({"error": "OAuth客户端ID错误"})).into_response();
        }
        if !client.unwrap().redirect_uris.iter().any(|uri| redirect_uri.starts_with(uri)) {
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
    if (user_state == UserState::Restricted || user_state == UserState::Locked)
        && user_info.restriction_end_time.is_some()
    {
        // 检查限制是否已过期
        if let Ok(end_time) =
            chrono::DateTime::parse_from_rfc3339(user_info.restriction_end_time.as_ref().unwrap())
        {
            if chrono::Utc::now() > end_time.with_timezone(&chrono::Utc) {
                // 解除限制
                let _ = db::set_user_state(&db_conn, &user_info.uid, UserState::Normal, "", "");
            }
        }
    }

    match user_state {
        UserState::Normal => {
            // 执行进才验证
            match zline::login_with_jincai(&state.http_client, user.clone(), pass.to_string()).await
            {
                Ok(external_cookie) => {
                    if sync_info {
                        // 获取外部用户信息
                        let (xuid, xuxm, student_id, gender) =
                            zline::get_external_user_info(&external_cookie)
                                .await
                                .unwrap_or_default();
                        db::set_user_flag(&db_conn, &user_info.uid, UserFlag::Normal).ok();
                        db::upsert_user(&db_conn, &user, &xuid, &xuxm, &student_id, &gender).ok();
                    }
                    db::record_login_success(
                        &db_conn,
                        &user_info.uid,
                        &client_ip,
                        &geo_location.country,
                        &geo_location.region,
                    )
                    .ok();

                    // 生成session ID并存储用户信息
                    let session_id = Uuid::new_v4().to_string();
                    state.session_store.lock().unwrap().insert(
                        session_id.clone(),
                        SessionData {
                            username: user.clone(),
                            created_at: std::time::SystemTime::now(),
                        },
                    );

                    // 验证成功，生成登录响应
                    return (
                        jar.add(create_sso_cookie(session_id, remember)),
                        handle_login_response(
                            &state,
                            user,
                            client_id,
                            redirect_uri,
                            payload.state,
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

                    // 检查是否应该锁定账户
                    if user_info.failed_attempts + 1
                        >= state.config.account_lockout.failed_attempts_threshold
                    {
                        // 计算锁定结束时间
                        let lockout_end = chrono::Utc::now()
                            + chrono::Duration::minutes(
                                state.config.account_lockout.lockout_duration_minutes as i64,
                            );
                        let _ = db::set_user_state(
                            &db_conn,
                            &user_info.uid,
                            UserState::Locked,
                            &format!(
                                "账户由于登录失败 {} 次已被锁定，将在 {} 自动解封",
                                user_info.failed_attempts + 1,
                                lockout_end.format("%Y-%m-%d %H:%M:%S")
                            ),
                            &lockout_end.to_rfc3339(),
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
                                zline::get_external_user_info(&external_cookie)
                                    .await
                                    .unwrap_or_default();
                            let _ = db::upsert_user(
                                &db_conn,
                                &user,
                                &xuid,
                                &xuxm,
                                &student_id,
                                &gender,
                            );
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
                                created_at: std::time::SystemTime::now(),
                            },
                        );

                        // 允许进入个人中心
                        return (
                            jar.add(create_sso_cookie(session_id, remember)),
                            Json(json!({
                                "code": "profile",
                                "redirect_uri": "/auth/profile",
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
                            // 计算锁定结束时间
                            let lockout_end = chrono::Utc::now()
                                + chrono::Duration::minutes(
                                    state.config.account_lockout.lockout_duration_minutes as i64,
                                );
                            let _ = db::set_user_state(
                                &db_conn,
                                &user_info.uid,
                                UserState::Locked,
                                &format!(
                                    "账户由于登录失败 {} 次已被锁定，将在 {} 自动解封",
                                    user_info.failed_attempts,
                                    lockout_end.format("%Y-%m-%d %H:%M:%S")
                                ),
                                &lockout_end.to_rfc3339(),
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
                    created_at: std::time::SystemTime::now(),
                },
            );
            return (
                jar.add(create_sso_cookie(session_id, remember)),
                handle_login_response(
                    &state,
                    user,
                    client_id,
                    redirect_uri,
                    payload.state,
                    is_direct_login,
                ),
            )
                .into_response();
        }
    }
}

async fn continue_handler(
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

    // 从session_store查询用户名
    let user = match state.session_store.lock().unwrap().get(&session_id) {
        Some(session) => session.username.clone(),
        None => return Json(json!({"error": "会话已过期"})).into_response(),
    };

    let client_id = payload.client_id.clone().unwrap_or_default();
    let redirect_uri = payload.redirect_uri.clone().unwrap_or_default();
    let is_direct_login = client_id.is_empty(); // 是否不带参数访问登录页面,即进入个人中心

    if !is_direct_login {
        let client = state.config.clients.iter().find(|c| c.client_id == client_id);
        if client.is_none()
            || !client.unwrap().redirect_uris.iter().any(|uri| redirect_uri.starts_with(uri))
        {
            return Json(json!({"error": "OAuth客户端ID错误"})).into_response();
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

    let user_state = user_info.state.try_into().unwrap_or_default();
    if (user_state == UserState::Restricted || user_state == UserState::Locked)
        && user_info.restriction_end_time.is_some()
    {
        // 检查限制是否已过期
        if let Ok(end_time) =
            chrono::DateTime::parse_from_rfc3339(user_info.restriction_end_time.as_ref().unwrap())
        {
            if chrono::Utc::now() > end_time.with_timezone(&chrono::Utc) {
                // 解除限制
                let _ = db::set_user_state(&db_conn, &user_info.uid, UserState::Normal, "", "");
            }
        }
    }

    match user_state {
        UserState::Normal | UserState::BypassExternal => {
            if !is_direct_login {
                return handle_login_response(
                    &state,
                    user,
                    client_id,
                    redirect_uri,
                    payload.state,
                    is_direct_login,
                );
            } else {
                // 允许进入个人中心
                return Json(json!({
                    "code": "profile",
                    "redirect_uri": "/auth/profile",
                    "is_direct_login": true
                }))
                .into_response();
            }
        }
        UserState::Restricted => {
            if is_direct_login {
                // 允许进入个人中心
                return Json(json!({
                    "code": "profile",
                    "redirect_uri": "/auth/profile",
                    "is_direct_login": true
                }))
                .into_response();
            } else {
                return Json(json!({"error": "账号处于限制状态,登录个人中心查看原因".to_string()}))
                    .into_response();
            }
        }
        UserState::Locked => {
            return Json(
                json!({"error": "账号处于锁定状态,请直接联系您的管理员。附加信息：".to_string() + &user_info.state_description.unwrap_or_else(|| "无".to_string())}),
            )
            .into_response();
        }
    }
}

async fn profile_api_handler(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let session_id = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "未登录"})),
            )
                .into_response();
        }
    };

    // 从session_store查询用户信息
    let username = match state.session_store.lock().unwrap().get(&session_id) {
        Some(session) => session.username.clone(),
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "会话无效或已过期"})),
            )
                .into_response();
        }
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    match db::get_user_full_info(&conn, &username) {
        Ok(Some(user_info)) => {
            let login_attempts =
                db::get_recent_login_attempts(&conn, &user_info.uid, 3).unwrap_or_default();
            Json(json!({
                "username": user_info.username,
                "role": user_info.role,
                "external_uid": user_info.external_uid,
                "student_id": user_info.student_id,
                "full_name": user_info.full_name,
                "gender": user_info.gender,
                "last_login_time": user_info.last_login_time,
                "state": user_info.state,
                "state_description": user_info.state_description,
                "restriction_end_time": user_info.restriction_end_time,
                "flag": user_info.flag,
                "login_attempts": login_attempts,
            }))
            .into_response()
        }
        Ok(None) => Json(json!({
            "username": username,
            "role": "user",
            "external_uid": "",
            "full_name": "",
            "state": 0,
            "state_description": null,
            "flag": 0,
            "login_attempts": [],
        }))
        .into_response(),
        Err(_) => Json(json!({
            "username": username,
            "role": "user",
            "external_uid": "",
            "full_name": "",
            "state": 0,
            "state_description": null,
            "flag": 0,
            "login_attempts": [],
        }))
        .into_response(),
    }
}

async fn token_exchange_handler(
    State(state): State<Arc<AppState>>,
    Form(payload): Form<TokenExchangeRequest>,
) -> Response {
    let is_valid = state
        .config
        .clients
        .iter()
        .any(|c| c.client_id == payload.client_id && c.client_secret == payload.client_secret);

    if !is_valid {
        return Json(json!({"error": "OAuth客户端ID错误"})).into_response();
    }

    let mut store = state.code_store.lock().unwrap();
    if let Some(session) = store.remove(&payload.code) {
        if session.client_id != payload.client_id {
            return Json(json!({"error": "OAuth客户端ID错误"})).into_response();
        }

        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: state.config.issuer.clone(),
            sub: session.username,
            aud: payload.client_id,
            iat: now,
            exp: now + 3600,
        };

        let keys = state.keys.read().unwrap().clone();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(keys.1.clone());

        let pem_bytes = keys
            .0
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map(|pem| pem.as_bytes().to_vec())
            .unwrap_or_default();

        let encoding_key = match jsonwebtoken::EncodingKey::from_rsa_pem(&pem_bytes) {
            Ok(key) => key,
            Err(_) => return Json(json!({"error": "密钥错误"})).into_response(),
        };

        match jsonwebtoken::encode(&header, &claims, &encoding_key) {
            Ok(token) => Json(json!({
                "access_token": token,
                "id_token": token,
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .into_response(),
            Err(_) => Json(json!({"error": "密钥错误"})).into_response(),
        }
    } else {
        Json(json!({"error": "OAuth授权码错误"})).into_response()
    }
}

async fn userinfo_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token_str = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    if token_str.is_none() {
        return Json(json!({"error": "未授权"})).into_response();
    }

    let keys = state.keys.read().unwrap();
    let pub_key = keys.0.to_public_key();
    let pub_pem_bytes = pub_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map(|pem| pem.as_bytes().to_vec())
        .unwrap_or_default();

    let decoding_key = match jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem_bytes) {
        Ok(key) => key,
        Err(_) => return Json(json!({"error": "密钥错误"})).into_response(),
    };

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_aud = false;

    match jsonwebtoken::decode::<Claims>(token_str.unwrap(), &decoding_key, &validation) {
        Ok(token_data) => {
            let username = &token_data.claims.sub;
            let client_id = &token_data.claims.aud;

            let conn = match state.db_pool.get() {
                Ok(c) => c,
                Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
            };

            let (role, xuid, xuxm, student_id, gender) =
                match db::get_user_full_info(&conn, username) {
                    Ok(Some(user_info)) => (
                        user_info.role,
                        user_info.external_uid,
                        user_info.full_name,
                        user_info.student_id.unwrap_or(String::new()),
                        user_info.gender.unwrap_or(String::new()),
                    ),
                    _ => (
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ),
                };

            let mut resp_data = json!({
                "sub": username,
                "preferred_username": username,
                "role": role,
            });

            if let Some(client_conf) =
                state.config.clients.iter().find(|c| &c.client_id == client_id)
            {
                for field in &client_conf.return_extra_userinfo {
                    match field.as_str() {
                        "external_uid" => resp_data["external_uid"] = json!(xuid),
                        "full_name" => resp_data["full_name"] = json!(xuxm),
                        "student_id" => resp_data["student_id"] = json!(student_id),
                        "gender" => resp_data["gender"] = json!(gender),
                        _ => {}
                    }
                }
            }

            Json(resp_data).into_response()
        }
        Err(_) => Json(json!({"error": "授权码错误"})).into_response(),
    }
}

async fn jwks_handler(State(state): State<Arc<AppState>>) -> Response {
    use rsa::traits::PublicKeyParts;

    let keys = state.keys.read().unwrap().clone();
    let pub_key = keys.0.to_public_key();

    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

    Json(json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": keys.1,
            "n": n,
            "e": e
        }]
    }))
    .into_response()
}

/// oidc端点解释,必须绑定到 /.well-known/openid-configuration
async fn oidc_config_handler(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({
        "issuer": state.config.issuer,
        "authorization_endpoint": format!("{}/auth/", state.config.issuer),
        "token_endpoint": format!("{}/auth/token", state.config.issuer),
        "userinfo_endpoint": format!("{}/auth/userinfo", state.config.issuer),
        "jwks_uri": format!("{}/auth/jwks", state.config.issuer),
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
    .into_response()
}

/// 向前端返回加密配置
async fn crypto_config_handler(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({
        "shared_key": state.config.frontend_crypto.shared_key
    }))
    .into_response()
}

/// 解密前端发送的AES-GCM加密负载
///
/// 前端使用共享密钥对用户名和密码进行AES-256-GCM加密，格式为：
/// Base64(Nonce(12字节) + Ciphertext + Tag) -> UTF8("username|password|timestamp")
///
/// 本函数验证时间戳以防止重放攻击，确保请求在指定的时间偏差范围内。
///
/// # 参数
/// - `payload_b64`: Base64编码的加密负载
/// - `key_hex`: 十六进制编码的AES-256密钥
/// - `skew`: 允许的最大时间偏差（秒），用于处理客户端和服务器时间不同步的情况
///
/// # 返回值
/// - `Ok((username, password))`: 解密和验证成功
/// - `Err(String)`: 解密失败或验证失败，包含错误描述
///
/// # 可能的错误
/// - 密钥格式无效（非十六进制）
/// - Base64解码失败
/// - 负载长度不足
/// - AES解密失败
/// - UTF-8编码转换失败
/// - 数据格式无效（不包含3个用'|'分隔的部分）
/// - 时间戳解析失败
/// - 请求已过期（时间偏差超过允许范围）
fn decrypt_frontend_payload(
    payload_b64: &str,
    key_hex: &str,
    skew: i64,
) -> Result<(String, String), String> {
    let key_bytes = hex::decode(key_hex).map_err(|_| "密钥格式无效")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let enc_data = general_purpose::STANDARD.decode(payload_b64).map_err(|_| "Base64解码失败")?;

    if enc_data.len() < 12 + 16 {
        return Err("负载长度无效".into());
    }

    let (nonce_bytes, encrypted_body) = enc_data.split_at(12);

    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), encrypted_body)
        .map_err(|e| format!("AES解密失败: {}", e))?;

    let s = String::from_utf8(decrypted).map_err(|_| "UTF8转换失败")?;
    let parts: Vec<&str> = s.split('|').collect();

    if parts.len() != 3 {
        return Err("数据格式无效".into());
    }

    let ts: i64 = parts[2].parse().map_err(|_| "时间戳无效")?;
    if (chrono::Utc::now().timestamp() - ts).abs() > skew {
        return Err("请求已过期".into());
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// 创建SSO会话Cookie
///
/// 生成一个HttpOnly的会话Cookie，用于追踪用户登录状态。
/// Cookie遵循SameSite=Lax策略以防止CSRF攻击。
///
/// # 参数
/// - `username`: 用户名，作为Cookie的值存储
/// - `remember`: 是否记住登录状态
///   - `true`: Cookie有效期为7天
///   - `false`: Cookie为会话Cookie，浏览器关闭时过期
///
/// # 返回值
/// 返回构建好的Cookie，可直接用于HTTP响应
pub fn create_sso_cookie(session_id: String, remember: bool) -> Cookie<'static> {
    let mut builder = Cookie::build(("sso_session", session_id))
        .path("/auth")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax);

    if remember {
        // 勾选记住我: 持久化cookie，7天有效期
        builder = builder.max_age(time::Duration::days(7));
    }
    // 未勾选记住我: 不设置max_age，让浏览器当作session cookie，关闭时自动删除

    builder.build()
}

/// 生成登录后的HTTP响应
///
/// 根据登录类型生成不同的响应：
/// - OAuth登录：生成授权码并返回给客户端，客户端稍后用该码换取token
/// - 个人中心登录：返回特殊响应表示用户可以进入个人中心
///
/// # 参数
/// - `state`: 应用状态，包含code_store用于存储授权码
/// - `username`: 认证的用户名
/// - `client_id`: 请求来源的应用ID（来自OAuth请求）
/// - `redirect_uri`: OAuth请求指定的重定向URI
/// - `oauth_state`: OAuth请求携带的state参数，用于防止CSRF
/// - `is_direct_login`: 是否为个人中心登录（true为不带client_id的直接访问）
///
/// # 返回值
/// 返回HTTP响应（JSON格式），包含：
/// - OAuth登录: `{code: "生成的授权码", redirect_uri, state}`
/// - 个人中心: `{code: "profile", redirect_uri: "/auth/profile", is_direct_login: true, state}`
fn handle_login_response(
    state: &Arc<AppState>,
    username: String,
    client_id: String,
    redirect_uri: String,
    oauth_state: Option<String>,
    is_direct_login: bool,
) -> Response {
    if !is_direct_login {
        // 常规登录
        let code = Uuid::new_v4().to_string();
        state.code_store.lock().unwrap().insert(
            code.clone(),
            AuthSession {
                username,
                client_id,
            },
        );

        Json(json!({
            "code": code,
            "redirect_uri": redirect_uri,
            "state": oauth_state
        }))
        .into_response()
    } else {
        // 个人中心登录
        return Json(json!({
            "code": "profile",
            "redirect_uri": "/auth/profile",
            "state": oauth_state,
            "is_direct_login": true
        }))
        .into_response();
    }
}
// ============ 主程序 ============

#[tokio::main]
async fn main() {
    let config_str = fs::read_to_string("config.json").expect("config.json not found");
    let mut config: Config =
        serde_json::from_str(&config_str).expect("Failed to parse config.json");
    if config.issuer.ends_with('/') {
        config.issuer.pop();
    }

    let db_path = "users.db".to_string();
    db::init_db(&db_path).expect("Failed to init database");

    // 创建数据库连接池
    let manager = r2d2_sqlite::SqliteConnectionManager::file(&db_path);
    let db_pool = r2d2::Pool::new(manager).expect("Failed to create database pool");

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let kid = Uuid::new_v4().to_string();

    let geoip_reader = match Reader::open_readfile(&config.geoip_mmdb_path) {
        Ok(reader) => Some(Arc::new(reader)),
        Err(err) => {
            eprintln!(
                "Warning: failed to open geoip mmdb file '{}': {}",
                config.geoip_mmdb_path, err
            );
            None
        }
    };

    let state = Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder().cookie_store(true).build().unwrap(),
        keys: RwLock::new(Arc::new((private_key, kid))),
        code_store: Mutex::new(HashMap::new()),
        session_store: Mutex::new(HashMap::new()),
        db_pool,
        geoip_reader,
        geoip_cache: Mutex::new(HashMap::new()),
    });

    // 预加载 students CSV 到内存缓存，避免每次查询都打开/读取文件
    if let Err(e) = zline::load_csv_cache("students_data.csv") {
        eprintln!("Warning: failed to load students_data.csv: {}", e);
    }

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(config.rate_limit.per_second as u32)
            .key_extractor(PeerIpKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/", get(|| async { Redirect::permanent("/auth/") })) // 根路径重定向
        .route("/auth", get(|| async { Redirect::permanent("/auth/") })) // 补全尾部斜杠
        .route("/auth/crypto-config", get(crypto_config_handler))
        .route("/auth/agreement", get(statics::agreement_html_handler)) // 静态 HTML
        .route("/auth/agreement.md", get(statics::agreement_md_handler)) // 静态 MD
        .route("/auth/login", post(login_handler))
        .route("/auth/", get(statics::login_page_handler))
        .route("/auth/continue", get(continue_handler))
        .route("/auth/logout", get(logout_handler))
        .route("/auth/profile", get(statics::profile_page_handler))
        .route("/auth/profile/api", get(profile_api_handler))
        .route("/auth/token", post(token_exchange_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route("/auth/jwks", get(jwks_handler))
        .route(
            "/.well-known/openid-configuration",
            get(oidc_config_handler),
        )
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST]),
        )
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("服务运行在 http://{}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
