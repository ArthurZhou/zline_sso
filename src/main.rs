use axum::{
    Router,
    extract::{Form, State},
    http::{Method, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
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
    time::Duration,
};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

// --- 结构体定义 ---

#[derive(Deserialize, Clone)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>, // 用于安全校验
}

#[derive(Deserialize, Clone)]
struct AppConfig {
    host: String,
    port: u16,
    issuer: String,
    key_rotation_hours: u64,
    clients: Vec<ClientConfig>,
}

struct ServerKeys {
    private_key: RsaPrivateKey,
    public_key_pem: String,
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
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String, // 前端 RSA 加密后的 base64
    password: String, // 前端 RSA 加密后的 base64
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

// --- 进才教育网关逻辑 ---

const JINCAI_PUB_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB";

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
    let text = resp.text().await.map_err(|_| "UTF8 Error".to_string())?;
    let id_pos = text.find("id=\"XToken\"").ok_or("XToken 标签未找到")?;
    let start = text[..id_pos].rfind('<').ok_or("标签起始缺失")?;
    let end = text[id_pos..].find('>').ok_or("标签结束缺失")? + id_pos;
    let tag = &text[start..=end];
    tag.split("value=\"")
        .nth(1)
        .and_then(|v| v.split('\"').next())
        .map(|v| v.to_string())
        .ok_or("XToken Value 缺失".into())
}

// --- 密钥管理逻辑 ---

fn generate_new_keys() -> ServerKeys {
    let mut rng = thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA 密钥生成失败");
    let public_key_pem = priv_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    ServerKeys {
        private_key: priv_key,
        public_key_pem,
        kid: Uuid::new_v4().to_string(),
    }
}

async fn key_rotation_task(state: Arc<AppState>) {
    let interval = Duration::from_secs(state.config.key_rotation_hours * 3600);
    loop {
        tokio::time::sleep(interval).await;
        let new_keys = Arc::new(generate_new_keys());
        {
            let mut w = state.keys.write().unwrap();
            *w = new_keys;
        }
        println!(
            "[系统] 密钥已轮换，新 KID: {}",
            state.keys.read().unwrap().kid
        );
    }
}

// --- Axum 路由处理器 ---

/// 异步读取外部 HTML 登录页
async fn login_page_handler() -> impl IntoResponse {
    match tokio::fs::read_to_string("static/login.html").await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Login page file not found").into_response(),
    }
}

async fn oidc_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "issuer": state.config.issuer,
        "authorization_endpoint": format!("{}/auth/", state.config.issuer),
        "token_endpoint": format!("{}/auth/token", state.config.issuer),
        "jwks_uri": format!("{}/auth/jwks", state.config.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

async fn jwks_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.keys.read().unwrap().clone();
    let pub_key = keys.private_key.to_public_key();
    let n = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

    Json(json!({
        "keys": [{
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": keys.kid, "n": n, "e": e
        }]
    }))
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // 1. 安全校验：检查 ClientID 和 Redirect URI 白名单
    let client = state
        .config
        .clients
        .iter()
        .find(|c| c.client_id == payload.client_id);
    match client {
        Some(c) => {
            let is_allowed = c  // 允许的 Redirect URI 必须是白名单中某个 URI 的前缀（不包括参数）
                .redirect_uris
                .iter()
                .any(|allowed_uri| payload.redirect_uri.starts_with(allowed_uri));

            if !is_allowed {
                return (StatusCode::FORBIDDEN, "未授权的 Redirect URI").into_response();
            }
        }
        None => return (StatusCode::BAD_REQUEST, "无效的 Client ID").into_response(),
    }

    // 2. 解密前端加密的身份信息
    let current_keys = state.keys.read().unwrap().clone();
    let user_bytes = general_purpose::STANDARD
        .decode(&payload.username)
        .unwrap_or_default();
    let pass_bytes = general_purpose::STANDARD
        .decode(&payload.password)
        .unwrap_or_default();

    let user = String::from_utf8(
        current_keys
            .private_key
            .decrypt(Pkcs1v15Encrypt, &user_bytes)
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    let pass = String::from_utf8(
        current_keys
            .private_key
            .decrypt(Pkcs1v15Encrypt, &pass_bytes)
            .unwrap_or_default(),
    )
    .unwrap_or_default();

    if user.is_empty() || pass.is_empty() {
        return (StatusCode::BAD_REQUEST, "解密失败或信息为空").into_response();
    }

    // 3. 进才网关交互
    let xtoken = match get_xtoken().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({"message": e}))).into_response(),
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
        if r.json::<Value>().await.unwrap_or_default()["succeed"] == "1" {
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
        Json(json!({"message": "身份验证失败"})),
    )
        .into_response()
}

async fn token_exchange_handler(
    State(state): State<Arc<AppState>>,
    Form(payload): Form<TokenExchangeRequest>,
) -> impl IntoResponse {
    let is_valid_client = state
        .config
        .clients
        .iter()
        .any(|c| c.client_id == payload.client_id && c.client_secret == payload.client_secret);

    if !is_valid_client {
        return (StatusCode::UNAUTHORIZED, "客户端凭据错误").into_response();
    }

    let mut store = state.code_store.lock().unwrap();
    if let Some(session) = store.remove(&payload.code) {
        if session.client_id != payload.client_id {
            return (StatusCode::UNAUTHORIZED, "Code 归属错误").into_response();
        }

        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: state.config.issuer.clone(),
            sub: session.username,
            aud: payload.client_id,
            iat: now,
            exp: now + 3600,
        };

        let current_keys = state.keys.read().unwrap().clone();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(current_keys.kid.clone());

        let private_key_pem = current_keys
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("私钥导出错误");
        let encoding_key =
            EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("编码密钥创建失败");

        let token = encode(&header, &claims, &encoding_key).unwrap();

        return (
            StatusCode::OK,
            Json(json!({
                "id_token": token,
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600
            })),
        )
            .into_response();
    }
    (StatusCode::UNAUTHORIZED, "授权码无效或已过期").into_response()
}

async fn get_provider_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.keys.read().unwrap().clone();
    Json(json!({ "pub_key": keys.public_key_pem }))
}

#[tokio::main]
async fn main() {
    // 1. 加载配置并清洗 Issuer（确保无末尾斜杠）
    let config_str = fs::read_to_string("config.json").expect("无法读取 config.json");
    let mut config: AppConfig = serde_json::from_str(&config_str).expect("config.json 格式错误");
    if config.issuer.ends_with('/') {
        config.issuer.pop();
    }

    // 2. 初始化状态
    let initial_keys = Arc::new(generate_new_keys());
    let state = Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap(),
        keys: RwLock::new(initial_keys),
        code_store: Mutex::new(HashMap::new()),
    });

    // 3. 启动密钥轮换
    let rotation_state = Arc::clone(&state);
    tokio::spawn(async move {
        key_rotation_task(rotation_state).await;
    });

    // 4. 构建路由
    let app = Router::new()
        .route("/auth/", get(login_page_handler)) // 登录页面
        .route("/auth/login", post(login_handler)) // 登录接口
        .route("/auth/token", post(token_exchange_handler)) // Token 交换
        .route("/auth/jwks", get(jwks_handler)) // 公钥集
        .route("/auth/provider-key", get(get_provider_key)) // 前端加密公钥
        .route("/.well-known/openid-configuration", get(oidc_config)) // OIDC 配置
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("[启动] SSO Provider 运行在 http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
