use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use axum::{
    Router,
    extract::{Form, State},
    http::{Method, StatusCode},
    response::{Html, IntoResponse, Json, Response},
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
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex, RwLock},
};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_http::cors::{Any, CorsLayer};
use std::net::SocketAddr;
use uuid::Uuid;

// --- 1. 配置与结构体定义 ---

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

/// 全局应用状态
struct AppState {
    config: AppConfig,
    http_client: reqwest::Client,
    keys: RwLock<Arc<ServerKeys>>,
    code_store: Mutex<HashMap<String, AuthSession>>,
    // 关键修复：存储数据库路径而非 Connection 对象。
    // rusqlite::Connection 是 !Send 的，放进 State 会导致 Handler 编译报错。
    db_path: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    encrypted_payload: String, // 前端加密的 username|password|ts
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

// --- 2. 数据库初始化 ---

fn init_db(path: &str) {
    let conn = Connection::open(path).expect("无法打开数据库文件");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            external_uid TEXT,
            full_name TEXT,
            role TEXT DEFAULT 'user'
        );",
        [],
    )
    .expect("初始化用户表失败");
}

// --- 3. 业务逻辑与加密工具 (全部保留) ---

const JINCAI_PUB_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB";

/// 使用金财公钥进行 RSA 加密
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

/// 获取金财系统的临时 XToken (爬虫逻辑)
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

/// 获取金财系统用户信息 (爬虫逻辑)
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

/// AES 解密前端传来的登录信息
fn decrypt_frontend_payload(
    payload: &str,
    key_hex: &str,
    skew: i64,
) -> Result<(String, String), String> {
    let key_bytes = hex::decode(key_hex).map_err(|_| "密钥 Hex 格式错误")?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let enc_data = general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| "Base64 解码失败")?;
    if enc_data.len() < 12 {
        return Err("Payload 长度不足".into());
    }
    let (nonce_bytes, ciphertext) = enc_data.split_at(12);
    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "AES 解密失败")?;
    let s = String::from_utf8(decrypted).map_err(|_| "UTF8 转换失败")?;
    let parts: Vec<&str> = s.split('|').collect();
    if parts.len() != 3 {
        return Err("Payload 格式错误".into());
    }
    let ts: i64 = parts[2].parse().map_err(|_| "时间戳格式错误")?;
    if (chrono::Utc::now().timestamp() - ts).abs() > skew {
        return Err("请求已过期 (Clock Skew)".into());
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

// --- 4. 路由处理器 (修复参数顺序) ---

/// OIDC 配置发现
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

/// 登录逻辑处理器 (核心修改：State 在前)
async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // 1. 客户端合法性检查
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

    // 2. 解密登录报文
    let (user, pass) = match decrypt_frontend_payload(
        &payload.encrypted_payload,
        &state.config.frontend_crypto.shared_key,
        state.config.frontend_crypto.max_clock_skew_secs,
    ) {
        Ok(data) => data,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };

    // 3. 对接金财系统
    let xtoken = match get_xtoken().await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"message": format!("获取 XToken 失败: {}", e)})),
            )
                .into_response();
        }
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
            // 4. 数据库持久化：即时打开连接
            let conn = Connection::open(&state.db_path).unwrap();
            let user_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)",
                    [&user],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if !user_exists {
                let new_id = Uuid::new_v4().to_string();
                if let Ok((xuid, xuxm)) = get_external_user_info(&pzl_cookie).await {
                    let _ = conn.execute("INSERT INTO users (id, username, external_uid, full_name, role) VALUES (?1, ?2, ?3, ?4, ?5)", [&new_id, &user, &xuid, &xuxm, "user"]);
                } else {
                    let _ = conn.execute(
                        "INSERT INTO users (id, username, role) VALUES (?1, ?2, ?3)",
                        [&new_id, &user, "user"],
                    );
                }
            }

            // 5. 发放 Code
            let code = Uuid::new_v4().to_string();
            state.code_store.lock().unwrap().insert(
                code.clone(),
                AuthSession {
                    username: user,
                    client_id: payload.client_id,
                },
            );
            return Json(json!({ "code": code, "redirect_uri": payload.redirect_uri, "state": payload.state })).into_response();
        }
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"message": "第三方验证失败"})),
    )
        .into_response()
}

/// Token 交换
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

/// UserInfo 接口
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

/// JWKS 导出
async fn jwks_handler(State(state): State<Arc<AppState>>) -> Response {
    let keys = state.keys.read().unwrap().clone();
    let pub_key = keys.private_key.to_public_key();
    let n = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    Json(json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "use": "sig", "kid": keys.kid, "n": n, "e": e }] })).into_response()
}

async fn get_crypto_config(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({ "shared_key": state.config.frontend_crypto.shared_key })).into_response()
}

async fn login_page_handler() -> Response {
    match tokio::fs::read_to_string("static/login.html").await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Login page not found").into_response(),
    }
}

// --- 5. 主程序入口 ---

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

    // 频率限制中间件 (使用配置值)
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1) 
            .burst_size(config.rate_limit.per_second as u32)
            .key_extractor(PeerIpKeyExtractor) 
            // 关键：开启此项后，如果有 Nginx 代理，它会读取 X-Forwarded-For
            // 如果没有 Nginx，它会回退到从 ConnectInfo 中提取 Peer IP
            .use_headers() 
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/auth/", get(login_page_handler))
        .route("/auth/token", post(token_exchange_handler))
        .route("/auth/jwks", get(jwks_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route("/auth/crypto-config", get(get_crypto_config))
        .route("/.well-known/openid-configuration", get(oidc_config))
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
        app.into_make_service_with_connect_info::<SocketAddr>()
    )
    .await
    .unwrap();
}
