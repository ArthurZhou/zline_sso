mod db;
mod statics;
mod zline;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use axum::{
    Form, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::header::HeaderValue,
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use base64::Engine;
use base64::engine::general_purpose;
use maxminddb::Reader;
use regex::Regex;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use uuid::Uuid;

// 会话 / 授权码 / GeoIP 缓存的有效期
const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600); // 会话 7 天
const CODE_TTL: Duration = Duration::from_secs(300); // 授权码 5 分钟
const GEOIP_CACHE_MAX: usize = 10_000;

#[derive(Deserialize, Clone)]
struct Config {
    host: String,
    port: u16,
    issuer: String,
    auth_path_prefix: String,
    rate_limit: RateLimitConfig,
    login_record_window: i32,
    geoip_mmdb_path: String,
    frontend_crypto: CryptoConfig,
    account_lockout: AccountLockoutConfig,
    cors_allowed_origins: Vec<String>,
    admin: AdminConfig,
    clients: Vec<ClientConfig>,
}

#[derive(Deserialize, Clone)]
struct AdminConfig {
    username: String,
    password_hash: String,
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
    nonce: Option<String>,
    remember: Option<bool>,
    sync_info: Option<bool>,
}

#[derive(Deserialize)]
struct TokenExchangeRequest {
    grant_type: String,
    code: String,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: String,
}

/// 管理员设置角色请求
#[derive(Deserialize)]
struct AdminRoleRequest {
    role: String,
}

/// 管理员封禁请求
#[derive(Deserialize)]
struct AdminBanRequest {
    reason: Option<String>,
    /// 封禁时长（小时），缺省/为 0 时表示永久封禁
    duration_hours: Option<i64>,
}

/// 管理员添加用户请求
#[derive(Deserialize)]
struct AdminAddUserRequest {
    username: String,
    /// 初始角色/标签（逗号分隔，可缺省，缺省为 "user"）
    role: Option<String>,
    full_name: Option<String>,
}

/// 员工（staff）标签管理请求
///
/// 用于为其他用户添加 / 移除标签。
#[derive(Deserialize)]
struct TagManageRequest {
    username: String,
    tag: String,
    /// 目标用户姓名（添加标签时用于确认用户身份，防止误加到他人）
    full_name: Option<String>,
}

/// 校验并规范化角色字符串（逗号分隔的多角色）。
///
/// 每个角色只能包含 ASCII 字母、数字、连字符 `-` 与下划线 `_`，
/// 且自动去除重复项与空白。返回规范化后的逗号分隔字符串。
fn validate_role_str(role: &str) -> Result<String, String> {
    let mut seen: Vec<String> = Vec::new();
    for part in role.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        if !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("角色 `{}` 只能包含字母、数字、连字符与下划线", t));
        }
        if !seen.iter().any(|s| s == t) {
            seen.push(t.to_string());
        }
    }
    Ok(seen.join(","))
}

/// 将角色字符串拆分为角色列表（按逗号分割并去除空白与空项）。
fn parse_roles(role: &str) -> Vec<String> {
    role.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 判断角色字符串中是否包含指定角色。
fn has_role(role: &str, target: &str) -> bool {
    parse_roles(role).iter().any(|r| r == target)
}

/// 向角色字符串中添加一个标签（若已存在则保持不变）。
fn add_tag_to_role(role: &str, tag: &str) -> String {
    let mut roles = parse_roles(role);
    if !roles.iter().any(|r| r == tag) {
        roles.push(tag.to_string());
    }
    roles.join(",")
}

/// 从角色字符串中移除一个标签（若不存在则保持不变）。
fn remove_tag_from_role(role: &str, tag: &str) -> String {
    parse_roles(role)
        .into_iter()
        .filter(|r| r != tag)
        .collect::<Vec<_>>()
        .join(",")
}

/// Access Token 声明（携带者令牌，用于 userinfo 端点）
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    iat: usize,
}

/// ID Token 声明（OIDC 标准声明，必须包含 nonce 以绑定授权请求）
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    azp: Option<String>,
    exp: usize,
    iat: usize,
    auth_time: usize,
    nonce: Option<String>,
}

#[derive(Clone)]
struct AuthSession {
    username: String,
    client_id: String,
    nonce: Option<String>,
    created_at: SystemTime,
}

struct SessionData {
    username: String,
    /// 是否通过管理员密码验证登录（仅管理员密码命中时为 true）。
    /// 管理员用户名同时可能是普通进才账户，因此不能仅凭用户名判定管理员。
    is_admin: bool,
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

    fn resolve_geo_location(&self, ip: &str) -> GeoLocation {        let default_unknown = GeoLocation {
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
        let country = data
            .get("country")
            .and_then(|c| c.get("names"))
            .or_else(|| {
                data.get("registered_country")
                    .and_then(|rc| rc.get("names"))
            })
            .and_then(|n| n.get("zh-CN").or(n.get("en")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "未知".to_string());

        // 6. 提取地区 (优先中文)
        let region = data
            .get("subdivisions")
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
                v4.is_link_local() // 169.254.0.0/16
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || // ::1
                // 检查是否为唯一本地地址 (fc00::/7) 或 链路本地地址 (fe80::/10)
                (v6.segments()[0] & 0xfe00) == 0xfc00 ||
                (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// 定期清理过期的会话、授权码与过大的 GeoIP 缓存，防止内存无界增长。
    fn cleanup_expired(&self) {
        self.session_store.lock().unwrap().retain(|_, s| {
            s.created_at
                .elapsed()
                .map(|d| d < SESSION_TTL)
                .unwrap_or(true)
        });

        self.code_store
            .lock()
            .unwrap()
            .retain(|_, c| c.created_at.elapsed().map(|d| d < CODE_TTL).unwrap_or(true));

        let mut geoip = self.geoip_cache.lock().unwrap();
        if geoip.len() > GEOIP_CACHE_MAX {
            geoip.clear();
        }
    }

    /// 判断给定用户名与密码是否为配置中的管理员账户。
    ///
    /// 该校验完全在本地完成（密码取 SHA-256 摘要后与配置中的摘要进行恒定时间比较），
    /// 因此管理员凭据绝不会被发送到外部（进才）系统验证。
    fn is_admin(&self, username: &str, password: &str) -> bool {
        if username != self.config.admin.username {
            return false;
        }
        let digest = sha256_hex(password);
        constant_time_eq(&digest, &self.config.admin.password_hash)
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
    // 仅当直接连接来自可信（局域网/回环）代理时才信任转发头，
    // 否则攻击者可通过伪造 X-Forwarded-For 污染审计日志与地理位置
    let peer_is_trusted = socket_addr
        .map(|addr| AppState::is_lan(addr.ip()))
        .unwrap_or(false);

    if peer_is_trusted {
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
    }

    // 使用直接连接地址
    socket_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "-1".to_string())
}

async fn logout_handler(
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
                created_at: std::time::SystemTime::now(),
            },
        );

        let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
        info!(username = %user, ip = %client_ip, "管理员登录成功");
        return (
            jar.add(create_sso_cookie(
                axum::extract::State(state.clone()),
                session_id,
                remember,
            )),
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
                            created_at: std::time::SystemTime::now(),
                        },
                    );

                    // 验证成功，生成登录响应
                    return (
                        jar.add(create_sso_cookie(
                            axum::extract::State(state.clone()),
                            session_id,
                            remember,
                        )),
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
                                created_at: std::time::SystemTime::now(),
                            },
                        );

                        // 允许进入个人中心
                        let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
                        return (
                            jar.add(create_sso_cookie(
                                axum::extract::State(state),
                                session_id,
                                remember,
                            )),
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
                    created_at: std::time::SystemTime::now(),
                },
            );
            return (
                jar.add(create_sso_cookie(
                    axum::extract::State(state.clone()),
                    session_id,
                    remember,
                )),
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
            return Json(json!({"error": "管理员账户不允许OAuth授权"}))
                .into_response();
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
                    client_id.to_string(),
                    redirect_uri.to_string(),
                    payload.state,
                    payload.nonce,
                    is_direct_login,
                );
            } else {
                // 允许进入个人中心
                let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
                return Json(json!({
                    "code": "profile",
                    "redirect_uri": redirect_uri,
                    "is_direct_login": true
                }))
                .into_response();
            }
        }
        UserState::Restricted => {
            if is_direct_login {
                // 允许进入个人中心
                let redirect_uri = format!("{}/profile", state.config.auth_path_prefix);
                return Json(json!({
                    "code": "profile",
                    "redirect_uri": redirect_uri,
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

    // 从session_store查询用户信息及是否管理员会话
    let (username, session_is_admin) =
        match state.session_store.lock().unwrap().get(&session_id) {
            Some(session) => (session.username.clone(), session.is_admin),
            None => {
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "会话无效或已过期"})),
                )
                    .into_response();
            }
        };

    // 管理员会话：返回管理员用户中心的专属信息
    if session_is_admin {
        return Json(json!({
            "username": username,
            "role": "admin",
            "external_uid": "",
            "full_name": "管理员",
            "student_id": "",
            "gender": "",
            "last_login_time": null,
            "state": 0,
            "state_description": null,
            "restriction_end_time": null,
            "flag": 1,
            "login_attempts": [],
            "is_admin": true,
        }))
        .into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    match db::get_user_full_info(&conn, &username) {
        Ok(Some(user_info)) => {
            let login_attempts = db::get_recent_login_attempts(
                &conn,
                &user_info.uid,
                state.config.login_record_window,
            )
            .unwrap_or_default();

            // 标签管理权限：仅非管理员会话中的 staff 用户可管理其自带的标签
            // （排除基线角色 `user` 与提权风险角色 `staff` / `admin`）
            let roles = parse_roles(&user_info.role);
            let is_staff = roles.iter().any(|r| r == "staff");
            let manageable_tags: Vec<String> = roles
                .iter()
                .filter(|r| {
                    r.as_str() != "staff" && r.as_str() != "admin" && r.as_str() != "user"
                })
                .cloned()
                .collect();

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
                "can_manage_tags": is_staff,
                "manageable_tags": manageable_tags,
            }))
            .into_response()
        }
        // 用户不存在或查询失败时返回默认信息
        _ => Json(json!({
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

/// 从会话 Cookie 校验管理员身份。
///
/// 仅当会话是通过管理员密码验证登录（`is_admin == true`）时才放行，
/// 返回管理员用户名；否则返回对应的 HTTP 错误响应。
fn require_admin(state: &Arc<AppState>, jar: &CookieJar) -> Result<String, Response> {
    let session_id = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => {
            return Err((axum::http::StatusCode::UNAUTHORIZED, Json(json!({"error":"未登录"}))).into_response());
        }
    };

    let (username, is_admin) = {
        let store = state.session_store.lock().unwrap();
        match store.get(&session_id) {
            Some(s) => (s.username.clone(), s.is_admin),
            None => {
                return Err((axum::http::StatusCode::UNAUTHORIZED, Json(json!({"error":"会话无效或已过期"}))).into_response());
            }
        }
    };

    if !is_admin {
        return Err((axum::http::StatusCode::FORBIDDEN, Json(json!({"error":"需要管理员权限"}))).into_response());
    }

    Ok(username)
}

/// 从会话 Cookie 校验登录身份。
///
/// 返回 `(用户名, 是否为管理员会话)`；未登录或会话失效时返回对应的 HTTP 错误响应。
fn require_session(
    state: &Arc<AppState>,
    jar: &CookieJar,
) -> Result<(String, bool), Response> {
    let session_id = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => {
            return Err((axum::http::StatusCode::UNAUTHORIZED, Json(json!({"error":"未登录"}))).into_response());
        }
    };

    let store = state.session_store.lock().unwrap();
    match store.get(&session_id) {
        Some(s) => Ok((s.username.clone(), s.is_admin)),
        None => Err(
            (axum::http::StatusCode::UNAUTHORIZED, Json(json!({"error":"会话无效或已过期"}))).into_response(),
        ),
    }
}

/// 校验当前会话是否为可进行标签管理的 staff 用户。
///
/// 仅当会话为普通（非管理员）登录，且当前用户的角色包含 `staff` 时放行，
/// 返回 `(用户名, 可管理标签列表)`。可管理标签 = 当前用户自带的标签
/// （不含基线角色 `user` 与提权风险角色 `staff` / `admin`）。
fn require_tag_manager(
    state: &Arc<AppState>,
    jar: &CookieJar,
) -> Result<(String, Vec<String>), Response> {
    let (username, is_admin) = match require_session(state, jar) {
        Ok(v) => v,
        Err(r) => return Err(r),
    };
    if is_admin {
        return Err(
            (axum::http::StatusCode::FORBIDDEN, Json(json!({"error":"管理员会话不支持标签管理"}))).into_response(),
        );
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => {
            return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"内部错误"}))).into_response());
        }
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => {
            return Err((axum::http::StatusCode::FORBIDDEN, Json(json!({"error":"用户不存在"}))).into_response());
        }
    };

    let roles = parse_roles(&user_info.role);
    if !roles.iter().any(|r| r == "staff") {
        return Err(
            (axum::http::StatusCode::FORBIDDEN, Json(json!({"error":"需要 staff 标签权限"}))).into_response(),
        );
    }

    let manageable: Vec<String> = roles
        .into_iter()
        .filter(|r| r != "staff" && r != "admin" && r != "user")
        .collect();
    Ok((username, manageable))
}

/// 查询用户列表（管理员）。
///
/// Query 参数：`keyword`（用户名/姓名/外部ID 模糊搜索）、`limit`、`offset`（分页）。
async fn admin_users_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let keyword = params.get("keyword").cloned().unwrap_or_default();
    let limit: i64 = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(50).clamp(1, 200);
    let offset: i64 = params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0).max(0);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let users = match db::list_users(&conn, &keyword, limit, offset) {
        Ok(u) => u,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let list: Vec<_> = users
        .iter()
        .map(|u| {
            json!({
                "uid": u.uid,
                "username": u.username,
                "role": u.role,
                "external_uid": u.external_uid,
                "full_name": u.full_name,
                "student_id": u.student_id,
                "gender": u.gender,
                "flag": u.flag,
                "state": u.state,
                "state_description": u.state_description,
                "restriction_end_time": u.restriction_end_time,
                "last_login_time": u.last_login_time,
                "failed_attempts": u.failed_attempts,
            })
        })
        .collect();

    Json(json!({ "users": list })).into_response()
}

/// 查询全量登录日志（管理员，跨所有用户）。
///
/// Query 参数：`keyword`（按用户名过滤）、`limit`、`offset`（分页）。
async fn admin_logs_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let keyword = params.get("keyword").cloned().unwrap_or_default();
    let limit: i64 = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100).clamp(1, 500);
    let offset: i64 = params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0).max(0);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let logs = match db::list_all_login_logs(&conn, &keyword, limit, offset) {
        Ok(l) => l,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    Json(json!({ "logs": logs })).into_response()
}

/// 封禁用户（管理员）。
///
/// Body：`{ "reason": 可选原因, "duration_hours": 可选封禁时长（小时），0/缺省为永久 }`。
async fn admin_ban_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
    Json(payload): Json<AdminBanRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    let reason = payload.reason.unwrap_or_else(|| "管理员封禁".to_string());
    let end_time = match payload.duration_hours {
        Some(h) if h > 0 => (chrono::Utc::now() + chrono::Duration::hours(h)).to_rfc3339(),
        _ => String::new(),
    };

    let description = if end_time.is_empty() {
        format!("{}（永久封禁）", reason)
    } else {
        let end_local = chrono::DateTime::parse_from_rfc3339(&end_time)
            .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|_| end_time.clone());
        format!("{}，解封时间 {}", reason, end_local)
    };

    if let Err(_) = db::set_user_state(&conn, &user_info.uid, UserState::Locked, &description, &end_time) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已封禁用户 {}", username) })).into_response()
}

/// 解封用户（管理员）。
async fn admin_unban_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    if let Err(_) = db::set_user_state(&conn, &user_info.uid, UserState::Normal, "", "") {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已解封用户 {}", username) })).into_response()
}

/// 设置用户角色（管理员）。
///
/// Body：`{ "role": "user" | "admin" | "staff" | "tag-a,tag-b" | ... }`。
/// 支持逗号分隔的多个角色，每个角色仅允许字母、数字、连字符与下划线。
async fn admin_role_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
    Json(payload): Json<AdminRoleRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let role = payload.role.trim().to_string();
    if role.is_empty() {
        return Json(json!({"error": "角色不能为空"})).into_response();
    }
    // 校验角色格式：逗号分隔的多角色，每个仅允许字母/数字/-/_，并规范化
    let role = match validate_role_str(&role) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return Json(json!({"error": "角色不能为空"})).into_response(),
        Err(e) => return Json(json!({"error": e})).into_response(),
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    if let Err(_) = db::set_user_role(&conn, &user_info.uid, &role) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已将 {} 的角色设置为 {}", username, role) }))
        .into_response()
}

/// 添加用户（管理员）。
///
/// Body：`{ "username": 必填, "role": 可选（默认 "user"）, "full_name": 可选 }`。
async fn admin_add_user_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<AdminAddUserRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let username = payload.username.trim().to_string();
    if username.is_empty() {
        return Json(json!({"error": "用户名不能为空"})).into_response();
    }

    // 初始角色：缺省为 "user"，否则校验格式
    let role = match payload.role {
        Some(r) => match validate_role_str(&r) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => "user".to_string(),
            Err(e) => return Json(json!({"error": e})).into_response(),
        },
        None => "user".to_string(),
    };

    let full_name = payload.full_name.unwrap_or_default().trim().to_string();

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    if let Ok(Some(_)) = db::get_user_full_info(&conn, &username) {
        return Json(json!({"error": "用户已存在"})).into_response();
    }

    if let Err(_) = db::add_user(&conn, &username, &role, &full_name) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已添加用户 {}（角色：{}）", username, role) }))
        .into_response()
}

/// 删除用户（管理员）。
async fn admin_delete_user_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let exists = db::get_user_full_info(&conn, &username)
        .map(|o| o.is_some())
        .unwrap_or(false);
    if !exists {
        return Json(json!({"error": "用户不存在"})).into_response();
    }

    if let Err(_) = db::delete_user(&conn, &username) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已删除用户 {}", username) })).into_response()
}

// ============ 员工（staff）标签管理 ============

/// 获取当前用户（staff）可管理的标签信息。
///
/// 返回 `{ can_manage, staff, role, manageable_tags }`。
/// 用于前端判断是否展示标签管理界面。
async fn profile_tags_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let (username, is_admin) = match require_session(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let roles = parse_roles(&user_info.role);
    let is_staff = roles.iter().any(|r| r == "staff");
    let manageable_tags: Vec<String> = roles
        .into_iter()
        .filter(|r| r != "staff" && r != "admin" && r != "user")
        .collect();

    Json(json!({
        "can_manage": is_staff && !is_admin,
        "staff": is_staff,
        "role": user_info.role,
        "manageable_tags": manageable_tags,
    }))
    .into_response()
}

/// 员工标签管理：查询已带标签的用户列表（仅 staff 用户可用）。
///
/// 仅返回至少带有一个非基线标签的用户，不向 staff 暴露完整用户列表。
/// Query 参数：`keyword`、`limit`、`offset`。
async fn profile_tag_users_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_tag_manager(&state, &jar) {
        return resp;
    }

    let keyword = params.get("keyword").cloned().unwrap_or_default();
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let users = match db::list_tagged_users(&conn, &keyword, limit, offset) {
        Ok(u) => u,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let list: Vec<_> = users
        .iter()
        .map(|u| {
            json!({
                "username": u.username,
                "full_name": u.full_name,
                "role": u.role,
            })
        })
        .collect();

    Json(json!({ "users": list })).into_response()
}

/// 员工标签管理：为其他用户添加标签。
///
/// Body：`{ "username": 目标用户, "full_name": 目标姓名, "tag": 要添加的标签 }`。
/// 服务端会按「用户名 + 姓名」双重确认目标用户，避免误加到他人。
/// 仅允许添加当前 staff 用户自带的标签（不含 `user` / `staff` / `admin`），且不能给自己添加。
async fn profile_tag_add_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<TagManageRequest>,
) -> Response {
    let (me, manageable) = match require_tag_manager(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let tag = payload.tag.trim().to_string();
    if !manageable.iter().any(|t| *t == tag) {
        return Json(json!({"error": "您不能管理该标签"})).into_response();
    }

    let target_username = payload.username.trim().to_string();
    if target_username.is_empty() {
        return Json(json!({"error": "用户名不能为空"})).into_response();
    }
    if target_username == me {
        return Json(json!({"error": "不能给自己添加标签"})).into_response();
    }

    // 添加标签必须提供目标姓名，服务端核对后再操作
    let full_name = payload
        .full_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if full_name.is_empty() {
        return Json(json!({"error": "请填写目标用户的姓名"})).into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let target = match db::get_user_full_info(&conn, &target_username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    // 姓名核对：与数据库中记录完全一致
    if target.full_name.trim() != full_name {
        return Json(json!({
            "error": "用户名与姓名不匹配，请核对后再试"
        }))
        .into_response();
    }

    if has_role(&target.role, &tag) {
        return Json(json!({
            "error": format!("用户 {} 已拥有标签 {}", target_username, tag)
        }))
        .into_response();
    }

    let new_role = add_tag_to_role(&target.role, &tag);
    if let Err(_) = db::set_user_role(&conn, &target.uid, &new_role) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({
        "success": true,
        "message": format!("已为 {}（{}）添加标签 {}", target_username, target.full_name, tag)
    }))
    .into_response()
}

/// 员工标签管理：移除其他用户的标签。
///
/// Body：`{ "username": 目标用户, "tag": 要移除的标签 }`。
/// 仅允许移除当前 staff 用户自带的标签（不含 `user` / `staff` / `admin`），且不能移除自己的标签。
async fn profile_tag_remove_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<TagManageRequest>,
) -> Response {
    let (me, manageable) = match require_tag_manager(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let tag = payload.tag.trim().to_string();
    if !manageable.iter().any(|t| *t == tag) {
        return Json(json!({"error": "您不能管理该标签"})).into_response();
    }

    let target_username = payload.username.trim().to_string();
    if target_username.is_empty() {
        return Json(json!({"error": "用户名不能为空"})).into_response();
    }
    // staff 不能移除自己的标签
    if target_username == me {
        return Json(json!({"error": "不能移除自己的标签"})).into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let target = match db::get_user_full_info(&conn, &target_username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    if !has_role(&target.role, &tag) {
        return Json(json!({
            "error": format!("用户 {} 没有标签 {}", target_username, tag)
        }))
        .into_response();
    }

    let new_role = remove_tag_from_role(&target.role, &tag);
    if let Err(_) = db::set_user_role(&conn, &target.uid, &new_role) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({
        "success": true,
        "message": format!("已移除 {} 的标签 {}", target_username, tag)
    }))
    .into_response()
}

/// 判断给定的 redirect_uri 是否与配置中的某个条目匹配。
///
/// - 若配置条目为纯字面量（不含正则元字符），则进行精确字符串比较（保持严格与向后兼容）；
/// - 否则将其作为正则表达式进行匹配，便于配置诸如 `^http://localhost:\d+/callback$` 的灵活规则。
fn redirect_matches(pattern: &str, uri: &str) -> bool {
    let is_regex = pattern.chars().any(|c| {
        matches!(
            c,
            '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\'
        )
    });

    if !is_regex {
        return pattern == uri;
    }

    Regex::new(pattern)
        .map(|re| re.is_match(uri))
        .unwrap_or(false)
}

/// 恒定时间字符串比较，避免对 client_secret 的时序侧信道攻击。
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// 计算字符串的 SHA-256 摘要，以十六进制字符串形式返回。
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

async fn token_exchange_handler(
    State(state): State<Arc<AppState>>,
    Form(payload): Form<TokenExchangeRequest>,
) -> Response {
    // OIDC token 端点必须校验 grant_type 为 authorization_code
    if payload.grant_type != "authorization_code" {
        return Json(json!({
            "error": "unsupported_grant_type",
            "error_description": "仅支持 authorization_code 授权类型"
        }))
        .into_response();
    }

    // 校验 client 凭据（secret 使用恒定时间比较，避免时序侧信道）
    let client_ok = state.config.clients.iter().any(|c| {
        c.client_id == payload.client_id
            && constant_time_eq(&c.client_secret, &payload.client_secret)
    });

    if !client_ok {
        return Json(json!({
            "error": "invalid_client",
            "error_description": "OAuth客户端ID错误"
        }))
        .into_response();
    }

    // OIDC 要求在 token 请求中携带 redirect_uri，且必须与授权请求时一致
    let requested_redirect = match &payload.redirect_uri {
        Some(uri) => uri,
        None => {
            return Json(json!({
                "error": "invalid_grant",
                "error_description": "缺少 redirect_uri"
            }))
            .into_response();
        }
    };

    let mut store = state.code_store.lock().unwrap();
    let session = match store.get(&payload.code) {
        Some(session) => session.clone(),
        None => {
            return Json(json!({
                "error": "invalid_grant",
                "error_description": "OAuth授权码错误"
            }))
            .into_response();
        }
    };

    if session.client_id != payload.client_id {
        return Json(json!({
            "error": "invalid_grant",
            "error_description": "OAuth客户端ID错误"
        }))
        .into_response();
    }

    // 授权码有效期校验
    if session
        .created_at
        .elapsed()
        .map(|d| d > CODE_TTL)
        .unwrap_or(false)
    {
        return Json(json!({
            "error": "invalid_grant",
            "error_description": "OAuth授权码已过期"
        }))
        .into_response();
    }

    // redirect_uri 校验：按该客户端配置的条目进行匹配（字面量精确匹配或正则匹配），
    // 兼容授权请求时实际使用的 redirect_uri，避免过于严格的精确比较导致校验失败。
    let redirect_ok = state
        .config
        .clients
        .iter()
        .find(|c| c.client_id == session.client_id)
        .map(|c| {
            c.redirect_uris
                .iter()
                .any(|pattern| redirect_matches(pattern, requested_redirect))
        })
        .unwrap_or(false);
    if !redirect_ok {
        return Json(json!({
            "error": "invalid_grant",
            "error_description": "OAuth重定向URI错误"
        }))
        .into_response();
    }

        let now = chrono::Utc::now().timestamp() as usize;

        let keys = state.keys.read().unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(keys.1.clone());

        let pem_bytes = keys
            .0
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map(|pem| pem.as_bytes().to_vec())
            .unwrap_or_default();

        let encoding_key = match jsonwebtoken::EncodingKey::from_rsa_pem(&pem_bytes) {
            Ok(key) => key,
            Err(err) => {
                error!(error = %err, "Token 签发失败：无法解析 RSA 私钥");
                return Json(json!({"error": "内部错误"})).into_response();
            }
        };

        // Access Token：携带者令牌，用于 userinfo 端点
        let access_claims = Claims {
            iss: state.config.issuer.clone(),
            sub: session.username.clone(),
            aud: payload.client_id.clone(),
            iat: now,
            exp: now + 3600,
        };

        // ID Token：与 access_token 分离，且必须携带 nonce（若授权请求提供了 nonce）
        let id_claims = IdTokenClaims {
            iss: state.config.issuer.clone(),
            sub: session.username.clone(),
            aud: payload.client_id.clone(),
            azp: Some(payload.client_id.clone()),
            iat: now,
            auth_time: now,
            exp: now + 3600,
            nonce: session.nonce.clone(),
        };

        let access_token = match jsonwebtoken::encode(&header, &access_claims, &encoding_key) {
            Ok(t) => t,
            Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
        };
        let id_token = match jsonwebtoken::encode(&header, &id_claims, &encoding_key) {
            Ok(t) => t,
            Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
        };

        info!(
            username = %session.username,
            client_id = %payload.client_id,
            "Token 签发成功"
        );

        // 仅在校验全部通过并成功签发 Token 后消费授权码，
        // 避免校验失败时误删除授权码，导致客户端重试时报“OAuth授权码错误”。
        store.remove(&payload.code);

        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
            "scope": "openid profile"
        }))
        .into_response()
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
    validation.validate_aud = false; // aud 为各客户端 client_id，解码后单独校验
    validation.set_issuer(&[state.config.issuer.clone()]);

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

            // 基础 OIDC 声明：sub 与由 sub 派生的 preferred_username
            let mut resp_data = json!({
                "sub": username,
                "preferred_username": username,
            });

            // 其余字段（含 role）严格遵循服务端 return_extra_userinfo 配置，
            // 未配置的字段一律不允许返回，防止超出授权范围泄露信息
            if let Some(client_conf) = state
                .config
                .clients
                .iter()
                .find(|c| &c.client_id == client_id)
            {
                for field in &client_conf.return_extra_userinfo {
                    match field.as_str() {
                        "external_uid" => resp_data["external_uid"] = json!(xuid),
                        "full_name" => resp_data["full_name"] = json!(xuxm),
                        "student_id" => resp_data["student_id"] = json!(student_id),
                        "gender" => resp_data["gender"] = json!(gender),
                        "role" => resp_data["role"] = json!(role),
                        _ => {}
                    }
                }
            }

            info!(
                username = %username,
                client_id = %client_id,
                "UserInfo 访问成功"
            );

            Json(resp_data).into_response()
        }
        Err(err) => {
            error!(error = %err, "UserInfo 访问失败：Token 校验失败");
            Json(json!({"error": "授权码错误"})).into_response()
        }
    }
}

async fn jwks_handler(State(state): State<Arc<AppState>>) -> Response {
    use rsa::traits::PublicKeyParts;

    let keys = state.keys.read().unwrap();
    let pub_key = keys.0.to_public_key();

    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

    Json(json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": keys.1.clone(),
            "n": n,
            "e": e
        }]
    }))
    .into_response()
}

/// oidc端点解释,必须绑定到 /.well-known/openid-configuration
async fn oidc_config_handler(State(state): State<Arc<AppState>>) -> Response {
    let prefix = &state.config.auth_path_prefix;
    let issuer = &state.config.issuer;

    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}{}/", issuer, prefix),
        "token_endpoint": format!("{}{}/token", issuer, prefix),
        "userinfo_endpoint": format!("{}{}/userinfo", issuer, prefix),
        "jwks_uri": format!("{}{}/jwks", issuer, prefix),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": [],
        "scopes_supported": ["openid", "profile"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "azp",
            "nonce",
            "preferred_username",
            "external_uid",
            "full_name",
            "student_id",
            "gender",
            "role"
        ]
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

    let enc_data = general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|_| "Base64解码失败")?;

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
fn create_sso_cookie(
    State(state): State<Arc<AppState>>,
    session_id: String,
    remember: bool,
) -> Cookie<'static> {
    let mut builder = Cookie::build(("sso_session", session_id))
        .path(state.config.auth_path_prefix.clone())
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
        return Json(json!({
            "code": "profile",
            "redirect_uri": redirect_uri,
            "state": oauth_state,
            "is_direct_login": true
        }))
        .into_response();
    }
}
// ============ 初始化函数 ============

fn init_app_state(config: Config) -> Arc<AppState> {
    let db_path = "users.db".to_string();
    db::init_db(&db_path).expect("Failed to init database");

    let manager = r2d2_sqlite::SqliteConnectionManager::file(&db_path);
    let db_pool = r2d2::Pool::new(manager).expect("Failed to create database pool");

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let kid = Uuid::new_v4().to_string();

    let geoip_reader = match Reader::open_readfile(&config.geoip_mmdb_path) {
        Ok(reader) => Some(Arc::new(reader)),
        Err(err) => {
            warn!(
                path = %config.geoip_mmdb_path, error = %err,
                "无法打开 GeoIP MMDB 文件，地理位置信息将不可用"
            );
            None
        }
    };

    Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap(),
        keys: RwLock::new(Arc::new((private_key, kid))),
        code_store: Mutex::new(HashMap::new()),
        session_store: Mutex::new(HashMap::new()),
        db_pool,
        geoip_reader,
        geoip_cache: Mutex::new(HashMap::new()),
    })
}

#[tokio::main]
async fn main() {
    // 初始化结构化日志：级别可通过 RUST_LOG 环境变量覆盖（默认 info）
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config_str = fs::read_to_string("config.toml").expect("config.toml not found");
    let mut config: Config =
        toml::from_str(&config_str).expect("Failed to parse config.toml");
    if config.issuer.ends_with('/') {
        config.issuer.pop();
    }
    info!(issuer = %config.issuer, host = %config.host, port = config.port,
        "配置文件加载完成");

    // 预加载 students CSV 到内存缓存
    if let Err(e) = zline::load_csv_cache("students_data.csv") {
        warn!("failed to load students_data.csv: {}", e);
    }

    let state = init_app_state(config.clone());
    let prefix = state.config.auth_path_prefix.clone();

    // 仅允许已注册客户端来源的 CORS（由配置的 cors_allowed_origins 指定）
    let allowed_origins: Vec<HeaderValue> = state
        .config
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    // 定期清理过期会话/授权码/GeoIP 缓存，防止内存无界增长
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                state.cleanup_expired();
            }
        });
    }

    // 速率限制配置
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(state.config.rate_limit.per_second as u32)
            .key_extractor(PeerIpKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );

    // 1. 构造受 prefix 影响的业务路由
    // 注意：这里原本的 "/" 建议改写成空字符串 "" 或者保持 "/" 但在外部处理冲突
    let auth_router = Router::new()
        .route("/", get(statics::login_page_handler)) // 对应 {prefix}/
        .route("/crypto-config", get(crypto_config_handler))
        .route("/agreement", get(statics::agreement_html_handler))
        .route("/agreement.md", get(statics::agreement_md_handler))
        .route("/login", post(login_handler))
        .route("/continue", get(continue_handler))
        .route("/logout", get(logout_handler))
        .route("/profile", get(statics::profile_page_handler))
        .route("/profile/api", get(profile_api_handler))
        .route("/profile/tags", get(profile_tags_handler))
        .route("/profile/tags/users", get(profile_tag_users_handler))
        .route("/profile/tags/add", post(profile_tag_add_handler))
        .route("/profile/tags/remove", post(profile_tag_remove_handler))
        .route("/token", post(token_exchange_handler))
        .route("/userinfo", get(userinfo_handler))
        .route("/jwks", get(jwks_handler));

    // 2. 构造主路由
    let app = Router::new()
        // 根目录直接跳转到 prefix/
        .route(
            "/",
            get({
                let p = prefix.clone();
                move || {
                    let path = format!("{p}");
                    async move { Redirect::temporary(&path) }
                }
            }),
        )
        // 使用 nest 挂载业务路由
        // Axum 的 nest 在路径不带斜杠时只匹配 {prefix}（不匹配 {prefix}/），
        // 因此这里显式补充 {prefix}/ 路由，使两种写法都能访问登录页。
        .route(
            &format!("{prefix}/"),
            get(statics::login_page_handler),
        )
        .nest(&prefix, auth_router)
        // 管理员 API（放在主路由、显式带 prefix）
        .route(
            &format!("{prefix}/admin/api/users"),
            get(admin_users_handler).post(admin_add_user_handler),
        )
        .route(&format!("{prefix}/admin/api/logs"), get(admin_logs_handler))
        .route(
            &format!("{prefix}/admin/api/users/:username/ban"),
            post(admin_ban_handler),
        )
        .route(
            &format!("{prefix}/admin/api/users/:username/unban"),
            post(admin_unban_handler),
        )
        .route(
            &format!("{prefix}/admin/api/users/:username/role"),
            post(admin_role_handler),
        )
        .route(
            &format!("{prefix}/admin/api/users/:username/delete"),
            post(admin_delete_user_handler),
        )
        // 固定路径不受 nest 影响
        .route(
            "/.well-known/openid-configuration",
            get(oidc_config_handler),
        )
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(allowed_origins)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST]),
        )
        // 请求级访问日志（method、uri、状态码、耗时）
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!(%addr, "服务启动");
    info!("服务运行在 http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
