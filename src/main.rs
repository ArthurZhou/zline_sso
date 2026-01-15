use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use axum::{
    Router,
    extract::{Form, Query, State},
    http::{Method, StatusCode, header},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use rand::thread_rng;
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex, RwLock},
};
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeFile;
use uuid::Uuid;

// --- 数据结构 ---

#[derive(Deserialize, Clone)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
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
struct AppConfig {
    host: String,
    port: u16,
    issuer: String,
    rate_limit: RateLimitConfig,
    frontend_crypto: CryptoConfig,
    clients: Vec<ClientConfig>,
}

struct ServerKeys {
    private_key: RsaPrivateKey,
    kid: String,
}

struct AuthSession {
    username: String,
    client_id: String,
}

struct AppState {
    config: AppConfig,
    http_client: reqwest::Client,
    keys: RwLock<Arc<ServerKeys>>,
    code_store: Mutex<HashMap<String, AuthSession>>,
    db_path: String,
}

#[derive(Deserialize, Debug, Clone)]
struct LoginRequest {
    encrypted_payload: Option<String>,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    remember: Option<bool>, // 新增字段，接收前端 checkbox 状态
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

const JINCAI_PUB_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB";

// --- 数据库操作 ---

fn init_db(path: &str) {
    let conn = Connection::open(path).expect("无法打开数据库文件");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            external_uid TEXT,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            state INTEGER DEFAULT 0,
            state_description TEXT
        );",
        [],
    )
    .expect("初始化用户表失败");
}

// --- 辅助工具函数 ---

fn encrypt_for_jincai(data: HashMap<String, String>) -> HashMap<String, String> {
    let pub_key_der = general_purpose::STANDARD.decode(JINCAI_PUB_KEY).unwrap();
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der).unwrap();
    let mut out = HashMap::new();
    let mut rng = thread_rng();
    for (k, v) in data {
        let enc = pub_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, v.as_bytes())
            .unwrap();
        out.insert(k, general_purpose::STANDARD.encode(enc));
    }
    out
}

async fn get_xtoken() -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://www.jincai.sh.cn/zlineauthrize/xlogin")
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let text = resp
        .text()
        .await
        .map_err(|_| "读取响应文本失败".to_string())?;
    let id_pos = text.find("id=\"XToken\"").ok_or("页面未找到 XToken 元素")?;
    let start = text[..id_pos].rfind('<').ok_or("标签解析错误")?;
    let end = text[id_pos..].find('>').ok_or("标签闭合缺失")? + id_pos;
    let tag = &text[start..=end];
    tag.split("value=\"")
        .nth(1)
        .and_then(|v| v.split('\"').next())
        .map(|v| v.to_string())
        .ok_or("XToken 值为空".into())
}

async fn get_external_user_info(pzl_cookie: &str) -> Result<(String, String), String> {
    let client = reqwest::Client::new();
    let url = "https://www.jincai.sh.cn/zlinesystem/xsso/gotox/JCAPW1002";
    let resp = client
        .get(url)
        .header("User-Agent", "Mozilla/5.0")
        .header("Cookie", format!("PZLSystemLogin={}", pzl_cookie))
        .send()
        .await
        .map_err(|e| format!("用户信息请求失败: {}", e))?;

    let text = resp.text().await.map_err(|_| "文本编码错误".to_string())?;
    let extract = |field: &str| -> Option<String> {
        let pattern = format!("name=\"{}\"", field);
        let pos = text.find(&pattern)?;
        let val_mark = "value=\"";
        let v_start = text[pos..].find(val_mark)? + pos + val_mark.len();
        let v_end = text[v_start..].find('\"')? + v_start;
        Some(text[v_start..v_end].to_string())
    };
    let xuid = extract("xuid").ok_or("解析 xuid 失败")?;
    let xuxm = extract("xuxm").ok_or("解析 xuxm 失败")?;
    Ok((xuid, xuxm))
}

fn decrypt_frontend_payload(
    payload_b64: &str,
    key_hex: &str,
    skew: i64,
) -> Result<(String, String), String> {
    let key_bytes = hex::decode(key_hex).map_err(|_| "密钥格式错误")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let enc_data = general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|_| "Base64解码失败")?;

    if enc_data.len() < 12 + 16 {
        return Err("Payload长度异常".into());
    }
    let (nonce_bytes, encrypted_body) = enc_data.split_at(12);

    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), encrypted_body)
        .map_err(|e| format!("AES解密失败: {}", e))?;

    let s = String::from_utf8(decrypted).map_err(|_| "UTF8转换失败")?;
    let parts: Vec<&str> = s.split('|').collect();
    if parts.len() != 3 {
        return Err("数据格式错误".into());
    }

    let ts: i64 = parts[2].parse().map_err(|_| "时间戳非法")?;
    if (chrono::Utc::now().timestamp() - ts).abs() > skew {
        return Err("请求已过期".into());
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn generate_new_keys() -> ServerKeys {
    let mut rng = thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 密钥失败");
    ServerKeys {
        private_key: priv_key,
        kid: Uuid::new_v4().to_string(),
    }
}

// --- 路由处理器 ---

async fn login_page_handler(
    jar: CookieJar,
    Query(_params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(cookie) = jar.get("sso_session") {
        let username = cookie.value().to_string();
        match tokio::fs::read_to_string("static/continue.html").await {
            Ok(html) => {
                // 将 HTML 中的占位符 {{username}} 替换为实际用户名
                let personalized_html = html.replace("{{username}}", &username);
                return Html(personalized_html).into_response();
            }
            Err(_) => return (StatusCode::NOT_FOUND, "continue.html不存在").into_response(),
        }
    }

    match tokio::fs::read_to_string("static/login.html").await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "login.html不存在").into_response(),
    }
}

async fn logout_handler(
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let query_str = serde_urlencoded::to_string(&params).unwrap_or_default();

    // 构建一个立即过期的 Cookie 来强制覆盖并清除
    let remove_cookie = Cookie::build(("sso_session", ""))
        .path("/")
        .http_only(true)
        .max_age(time::Duration::ZERO) // 立即过期
        .build();

    (
        jar.add(remove_cookie),
        // 重定向回 /auth/ 并带上原始参数，此时因为 Cookie 已删，login_page_handler 会渲染 login.html
        Redirect::to(&format!("/auth/?{}", query_str)),
    )
}

async fn continue_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(payload): Query<LoginRequest>,
) -> Response {
    // 1. 检查 Cookie 是否存在
    let username = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => return (StatusCode::UNAUTHORIZED, "会话已过期").into_response(),
    };

    // 2. 【关键修复】必须校验 Client ID 是否在 config.json 中
    let client = state.config.clients.iter().find(|c| c.client_id == payload.client_id);
    if client.is_none() {
        return (StatusCode::BAD_REQUEST, "无效的 Client ID").into_response();
    }

    // 3. 【关键修复】必须校验重定向 URI 是否合法
    if !client.unwrap().redirect_uris.iter().any(|uri| payload.redirect_uri.starts_with(uri)) {
        return (StatusCode::FORBIDDEN, "无效的重定向 URI").into_response();
    }

    // 4. 检查数据库中用户状态
    let conn = Connection::open(&state.db_path).unwrap();
    let user_row: Option<(i32, Option<String>)> = conn
        .query_row(
            "SELECT state, state_description FROM users WHERE username = ?1",
            [&username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap();

    if let Some((st, desc)) = user_row {
        if st == 1 || st == 2 {
            return (StatusCode::FORBIDDEN, desc.unwrap_or_else(|| "账户已锁定".into())).into_response();
        }
    }

    // 5. 调用你已有的函数发放 code 并返回 JSON
    issue_code_response(
        &state,
        username,
        payload.client_id,
        payload.redirect_uri,
        payload.state,
    )
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let client = state
        .config
        .clients
        .iter()
        .find(|c| c.client_id == payload.client_id);
    if client.is_none() {
        return (StatusCode::BAD_REQUEST, "无效的 Client ID").into_response();
    }
    if !client
        .unwrap()
        .redirect_uris
        .iter()
        .any(|uri| payload.redirect_uri.starts_with(uri))
    {
        return (StatusCode::FORBIDDEN, "无效的重定向 URI").into_response();
    }

    let enc_payload = match &payload.encrypted_payload {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "Missing payload").into_response(),
    };
    let (user, pass) = match decrypt_frontend_payload(
        enc_payload,
        &state.config.frontend_crypto.shared_key,
        state.config.frontend_crypto.max_clock_skew_secs,
    ) {
        Ok(data) => data,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };

    let remember = payload.remember.unwrap_or(false); // 获取记住我选项

    let conn = Connection::open(&state.db_path).unwrap();

    let local_user: Option<(i32, Option<String>, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT state, state_description, external_uid, full_name FROM users WHERE username = ?1",
            [&user],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().unwrap();

    if let Some((st, desc, xuid, xuxm)) = local_user {
        // State 拒绝系统：状态为 1, 2 时向前端返回 description
        if st == 1 || st == 2 {
            return (
                StatusCode::FORBIDDEN,
                desc.unwrap_or_else(|| "账号被限制".into()),
            )
                .into_response();
        }

        // Bypass 逻辑 (State 3)
        if st == 3 {
            return (
                jar.add(create_sso_cookie(user.clone(), remember)),
                issue_code_response(
                    &state,
                    user,
                    payload.client_id,
                    payload.redirect_uri,
                    payload.state,
                ),
            )
                .into_response();
        }

        // 自动同步检查：检查 xuid 和 xuxm 是否有空字段
        if xuid.is_none()
            || xuxm.is_none()
            || xuid.as_ref().unwrap().is_empty()
            || xuxm.as_ref().unwrap().is_empty()
        {
            return perform_jincai_login_and_sync(state, jar, user, pass, remember, payload, conn)
                .await;
        }
    } else {
        return perform_jincai_login_and_sync(state, jar, user, pass, remember, payload, conn)
            .await;
    }

    perform_jincai_login_and_sync(state, jar, user, pass, remember, payload, conn).await
}

async fn perform_jincai_login_and_sync(
    state: Arc<AppState>,
    jar: CookieJar,
    user: String,
    pass: String,
    remember: bool,
    payload: LoginRequest,
    conn: Connection,
) -> Response {
    let xtoken = match get_xtoken().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("XToken 失败: {}", e)).into_response(),
    };

    let mut data = HashMap::new();
    data.insert("XToken".into(), xtoken);
    data.insert("pzlusername".into(), user.clone());
    data.insert("pzlpassword".into(), pass);

    let encrypted_body = encrypt_for_jincai(data);
    let resp = state
        .http_client
        .post("https://www.jincai.sh.cn/zlineauthrize/xlogin/sysxlogin")
        .form(&encrypted_body)
        .send()
        .await;

    if let Ok(r) = resp {
        let mut pzl_cookie = String::new();
        for cookie in r.cookies() {
            if cookie.name() == "PZLSystemLogin" {
                pzl_cookie = cookie.value().to_string();
            }
        }

        if r.json::<Value>().await.unwrap_or_default()["succeed"] == "1" {
            let (xuid, xuxm) = get_external_user_info(&pzl_cookie)
                .await
                .unwrap_or(("unknown".into(), "unknown".into()));

            let _ = conn.execute(
                "INSERT INTO users (id, username, external_uid, full_name, role, state) 
                 VALUES (?1, ?2, ?3, ?4, 'user', 0)
                 ON CONFLICT(username) DO UPDATE SET external_uid=?3, full_name=?4",
                params![Uuid::new_v4().to_string(), user, xuid, xuxm],
            );

            return (
                jar.add(create_sso_cookie(user.clone(), remember)),
                issue_code_response(
                    &state,
                    user,
                    payload.client_id,
                    payload.redirect_uri,
                    payload.state,
                ),
            )
                .into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, "第三方验证失败").into_response()
}

// 修改原有的函数，增加 remember 参数
fn create_sso_cookie(username: String, remember: bool) -> Cookie<'static> {
    let mut builder = Cookie::build(("sso_session", username))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax); // 推荐增加 SameSite 属性

    if remember {
        // 如果勾选记住我，设置 7 天有效期
        builder = builder.max_age(time::Duration::days(7));
    } else {
        builder = builder.max_age(time::Duration::seconds(1));
    }
    // 注意：如果不设置 max_age，默认就是 Session Cookie，浏览器关闭后自动删除

    builder.build()
}

fn issue_code_response(
    state: &Arc<AppState>,
    username: String,
    client_id: String,
    redirect_uri: String,
    oauth_state: Option<String>,
) -> Response {
    let code = Uuid::new_v4().to_string();
    state.code_store.lock().unwrap().insert(
        code.clone(),
        AuthSession {
            username,
            client_id,
        },
    );
    Json(json!({ "code": code, "redirect_uri": redirect_uri, "state": oauth_state }))
        .into_response()
}

// --- OIDC 处理器 (保持原样) ---

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
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }

    let mut store = state.code_store.lock().unwrap();
    if let Some(session) = store.remove(&payload.code) {
        if session.client_id != payload.client_id {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: state.config.issuer.clone(),
            sub: session.username.clone(),
            aud: payload.client_id,
            iat: now,
            exp: now + 3600,
        };
        let current_keys = state.keys.read().unwrap().clone();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(current_keys.kid.clone());
        let encoding_key = EncodingKey::from_rsa_pem(
            current_keys
                .private_key
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();
        Json(json!({ "access_token": token, "id_token": token, "token_type": "Bearer", "expires_in": 3600 })).into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_code"})),
        )
            .into_response()
    }
}

async fn userinfo_handler(
    State(state): State<Arc<AppState>>,
    header: axum::http::HeaderMap,
) -> Response {
    let token_str = header
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    if token_str.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let keys = state.keys.read().unwrap();
    let decoding_key = DecodingKey::from_rsa_pem(
        keys.private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    match jsonwebtoken::decode::<Claims>(token_str.unwrap(), &decoding_key, &validation) {
        Ok(token_data) => {
            let conn = Connection::open(&state.db_path).unwrap();
            let role: String = conn
                .query_row(
                    "SELECT role FROM users WHERE username = ?1",
                    [&token_data.claims.sub],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| "user".to_string());
            Json(json!({ "sub": token_data.claims.sub, "role": role, "preferred_username": token_data.claims.sub })).into_response()
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_token"})),
        )
            .into_response(),
    }
}

async fn jwks_handler(State(state): State<Arc<AppState>>) -> Response {
    let keys = state.keys.read().unwrap().clone();
    let pub_key = keys.private_key.to_public_key();
    let n = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    Json(json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "use": "sig", "kid": keys.kid, "n": n, "e": e }] })).into_response()
}

async fn crypto_config_handler(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({
        "shared_key": state.config.frontend_crypto.shared_key
    }))
    .into_response()
}

async fn font_handler() -> impl IntoResponse {
    match tokio::fs::read("static/font.woff").await {
        Ok(data) => (
            [
                (header::CONTENT_TYPE, "font/woff"),
                (header::CACHE_CONTROL, "public, max-age=2592000, immutable"),
            ],
            data,
        ).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[tokio::main]
async fn main() {
    let config_str = fs::read_to_string("config.json").expect("config.json 缺失");
    let mut config: AppConfig = serde_json::from_str(&config_str).expect("解析 config.json 失败");
    if config.issuer.ends_with('/') {
        config.issuer.pop();
    }

    let db_path = "users.db".to_string();
    init_db(&db_path);

    let state = Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap(),
        keys: RwLock::new(Arc::new(generate_new_keys())),
        code_store: Mutex::new(HashMap::new()),
        db_path,
    });

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
        .route("/auth/crypto-config", get(crypto_config_handler))
        .route_service("/auth/agreement", ServeFile::new("static/agreement.html"))
        .route_service("/auth/agreement.md", ServeFile::new("static/AGREEMENT.md"))
        .route("/auth/font.woff", get(font_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/", get(login_page_handler))
        .route("/auth/continue", get(continue_handler))
        .route("/auth/logout", get(logout_handler))
        .route("/auth/token", post(token_exchange_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route("/auth/jwks", get(jwks_handler))
        .route(
            "/.well-known/openid-configuration",
            get(|s| async { oidc_config(s).await }),
        )
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST]),
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

async fn oidc_config(State(state): State<Arc<AppState>>) -> Response {
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
