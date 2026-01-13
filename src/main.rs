use axum::{
    Router,
    extract::{Form, State, Query},
    http::{Method, StatusCode, header},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use rand::thread_rng;
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex, RwLock},
};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use rusqlite::{params, Connection};

// --- 结构体定义 ---

#[derive(Deserialize, Clone)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct RateLimitConfig {
    per_second: u64,
    burst: u32,
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
    db: Mutex<Connection>,
}

#[derive(Deserialize)]
struct LoginRequest {
    encrypted_payload: String, 
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
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

// --- 数据库初始化 ---

fn init_db() -> Connection {
    let conn = Connection::open("users.db").expect("无法打开数据库");
    // 提高写入性能和持久化可靠性
    conn.execute("PRAGMA journal_mode = WAL;", []).ok();
    conn.execute("PRAGMA synchronous = NORMAL;", []).ok();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            role TEXT NOT NULL
        )",
        [],
    ).expect("初始化表失败");
    conn
}

// --- 进才教育网关逻辑与加密辅助 (保持不变) ---
const JINCAI_PUB_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB";

fn encrypt_for_jincai(data: HashMap<String, String>) -> HashMap<String, String> {
    let pub_key_der = general_purpose::STANDARD.decode(JINCAI_PUB_KEY).unwrap();
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der).unwrap();
    let mut out = HashMap::new();
    let mut rng = thread_rng();
    for (k, v) in data {
        let enc = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, v.as_bytes()).unwrap();
        out.insert(k, general_purpose::STANDARD.encode(enc));
    }
    out
}

async fn get_xtoken() -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client.get("https://www.jincai.sh.cn/zlineauthrize/xlogin").header("User-Agent", "Mozilla/5.0").send().await.map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|_| "UTF8 Error".to_string())?;
    let id_pos = text.find("id=\"XToken\"").ok_or("XToken 标签未找到")?;
    let start = text[..id_pos].rfind('<').ok_or("标签起始缺失")?;
    let end = text[id_pos..].find('>').ok_or("标签结束缺失")? + id_pos;
    let tag = &text[start..=end];
    tag.split("value=\"").nth(1).and_then(|v| v.split('\"').next()).map(|v| v.to_string()).ok_or("XToken Value 缺失".into())
}

fn decrypt_frontend_payload(payload: &str, key_hex: &str, skew: i64) -> Result<(String, String), String> {
    let key_bytes = hex::decode(key_hex).map_err(|_| "Hex Decode Key Error")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let encrypted_data = general_purpose::STANDARD.decode(payload).map_err(|_| "Base64 Decode Error")?;
    if encrypted_data.len() < 12 { return Err("Payload too short".into()); }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|_| "AES Decrypt Error")?;
    let s = String::from_utf8(decrypted).map_err(|_| "UTF8 Error")?;
    let parts: Vec<&str> = s.split('|').collect();
    if parts.len() != 3 { return Err("Invalid format".into()); }
    let timestamp: i64 = parts[2].parse().map_err(|_| "Timestamp Error")?;
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > skew { return Err("Request expired".into()); }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn generate_new_keys() -> ServerKeys {
    let mut rng = thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA 密钥生成失败");
    ServerKeys { private_key: priv_key, kid: Uuid::new_v4().to_string() }
}

// --- 处理器 ---

async fn get_crypto_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "shared_key": state.config.frontend_crypto.shared_key }))
}

async fn userinfo_handler(
    State(state): State<Arc<AppState>>,
    header: axum::http::HeaderMap,
) -> impl IntoResponse {
    // 1. 获取 Authorization: Bearer <token>
    let auth_header = header.get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token_str = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response(),
    };

    // 2. 解析 Token 获取用户名 (sub)
    let keys = state.keys.read().unwrap();
    // 使用 RSA 公钥校验签名
    let decoding_key = DecodingKey::from_rsa_pem(
        keys.private_key.to_public_key().to_public_key_pem(LineEnding::LF).unwrap().as_bytes()
    ).unwrap();
    
    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    // 忽略 aud 校验以简化测试，或从 config 加载
    validation.validate_aud = false; 

    let token_data = match jsonwebtoken::decode::<Claims>(token_str, &decoding_key, &validation) {
        Ok(data) => data,
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_token"}))).into_response(),
    };

    let username = token_data.claims.sub;

    // 3. 从数据库查询 Role
    let conn = state.db.lock().unwrap();
    let role: String = conn.query_row(
        "SELECT role FROM users WHERE username = ?1",
        [&username],
        |row| row.get(0),
    ).unwrap_or_else(|_| "user".to_string());

    // 4. 返回对应用户信息
    Json(json!({
        "sub": username,
        "role": role,
        "preferred_username": username
    })).into_response()
}

async fn oidc_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "issuer": state.config.issuer,
        "authorization_endpoint": format!("{}/auth/", state.config.issuer),
        "token_endpoint": format!("{}/auth/token", state.config.issuer),
        "userinfo_endpoint": format!("{}/auth/userinfo", state.config.issuer),
        "jwks_uri": format!("{}/auth/jwks", state.config.issuer),
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

// ... login_handler, token_exchange_handler, jwks_handler (逻辑与之前一致) ...
// (此处省略重复的 login_handler 等代码以保持简洁，逻辑按原样保留)
async fn login_page_handler() -> impl IntoResponse {
    match tokio::fs::read_to_string("static/login.html").await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Login page file not found").into_response(),
    }
}

async fn jwks_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.keys.read().unwrap().clone();
    let pub_key = keys.private_key.to_public_key();
    let n = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    Json(json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "use": "sig", "kid": keys.kid, "n": n, "e": e }] }))
}

async fn login_handler(State(state): State<Arc<AppState>>, Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    let client = state.config.clients.iter().find(|c| c.client_id == payload.client_id);
    match client {
        Some(c) => {
            if !c.redirect_uris.iter().any(|uri| payload.redirect_uri.starts_with(uri)) {
                return (StatusCode::FORBIDDEN, "未授权的 Redirect URI").into_response();
            }
        }
        None => return (StatusCode::BAD_REQUEST, "无效的 Client ID").into_response(),
    }

    let (user, pass) = match decrypt_frontend_payload(&payload.encrypted_payload, &state.config.frontend_crypto.shared_key, state.config.frontend_crypto.max_clock_skew_secs) {
        Ok(data) => data,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };

    let xtoken = match get_xtoken().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({"message": e}))).into_response(),
    };

    let mut data = HashMap::new();
    data.insert("XToken".into(), xtoken);
    data.insert("pzlusername".into(), user.clone());
    data.insert("pzlpassword".into(), pass);

    let encrypted_body = encrypt_for_jincai(data);
    let resp = state.http_client.post("https://www.jincai.sh.cn/zlineauthrize/xlogin/sysxlogin").form(&encrypted_body).send().await;

    if let Ok(r) = resp {
        if r.json::<Value>().await.unwrap_or_default()["succeed"] == "1" {
            let code = Uuid::new_v4().to_string();
            state.code_store.lock().unwrap().insert(code.clone(), AuthSession { username: user, client_id: payload.client_id });
            return Json(json!({ "code": code, "redirect_uri": payload.redirect_uri, "state": payload.state })).into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, Json(json!({"message": "身份验证失败"}))).into_response()
}

async fn token_exchange_handler(
    State(state): State<Arc<AppState>>,
    // 关键：Authlib 发送的是 Form 表单，不是 Json
    Form(payload): Form<TokenExchangeRequest>,
) -> impl IntoResponse {
    // 1. 验证客户端
    let is_valid_client = state.config.clients.iter().any(|c| 
        c.client_id == payload.client_id && c.client_secret == payload.client_secret
    );
    
    if !is_valid_client {
        return (
            StatusCode::UNAUTHORIZED, 
            Json(json!({"error": "invalid_client"}))
        ).into_response();
    }

    // 2. 校验并提取 Code
    let mut store = state.code_store.lock().unwrap();
    if let Some(session) = store.remove(&payload.code) {
        if session.client_id != payload.client_id {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_grant"}))).into_response();
        }

        // --- 核心：自动写入数据库 ---
        {
            let conn = state.db.lock().unwrap();
            // 使用 INSERT OR IGNORE 确保用户不存在时才创建，存在则不报错
            let _ = conn.execute(
                "INSERT OR IGNORE INTO users (username, role) VALUES (?1, ?2)",
                [&session.username, "user"],
            );
            // SQLite 默认开启自动提交，数据会立即写入 users.db 文件
        }

        // 3. 生成 JWT
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: state.config.issuer.clone(),
            sub: session.username.clone(), // 这里的 sub 会被 userinfo 接口读取
            aud: payload.client_id,
            iat: now,
            exp: now + 3600,
        };

        let current_keys = state.keys.read().unwrap().clone();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(current_keys.kid.clone());

        let private_key_pem = current_keys.private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // 4. 返回 JSON (这是 Python 能解析成功的关键)
        Json(json!({
            "access_token": token,
            "id_token": token,
            "token_type": "Bearer",
            "expires_in": 3600
        })).into_response()
    } else {
        (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_code_or_expired"}))).into_response()
    }
}
// --- Main ---

#[tokio::main]
async fn main() {
    let config_str = fs::read_to_string("config.json").expect("无法读取 config.json");
    let mut config: AppConfig = serde_json::from_str(&config_str).expect("config.json 格式错误");
    if config.issuer.ends_with('/') { config.issuer.pop(); }

    let state = Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder().cookie_store(true).build().unwrap(),
        keys: RwLock::new(Arc::new(generate_new_keys())),
        code_store: Mutex::new(HashMap::new()),
        db: Mutex::new(init_db()),
    });

    let rate_limit_middleware = tower::ServiceBuilder::new()
        .layer(axum::error_handling::HandleErrorLayer::new(|_| async { (StatusCode::TOO_MANY_REQUESTS, Json(json!({"message": "服务器繁忙"}))) }))
        .layer(tower::buffer::BufferLayer::new(1024))
        .layer(tower::limit::RateLimitLayer::new(config.rate_limit.per_second, std::time::Duration::from_secs(1)));

    let app = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/auth/", get(login_page_handler))
        .route("/auth/token", post(token_exchange_handler))
        .route("/auth/jwks", get(jwks_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route("/auth/crypto-config", get(get_crypto_config))
        .route("/.well-known/openid-configuration", get(oidc_config))
        .layer(rate_limit_middleware)
        .layer(CorsLayer::new().allow_origin(Any).allow_methods([Method::GET, Method::POST]).allow_headers(Any))
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("[启动] SSO Provider 运行在 http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}