use axum::{
    extract::{State, Form}, http::{StatusCode, Method}, response::{IntoResponse, Json},
    routing::{get, post}, Router,
};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use rand::thread_rng;
use rsa::{pkcs8::{EncodePublicKey, EncodePrivateKey, LineEnding, DecodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::{Arc, Mutex, RwLock}, fs, time::Duration};
use tower_http::{services::ServeDir, cors::{CorsLayer, Any}};
use uuid::Uuid;

// --- 结构体定义 ---

#[derive(Deserialize, Clone)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    #[allow(dead_code)]
    redirect_uris: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct AppConfig {
    host: String,
    port: u16,
    issuer: String,
    key_rotation_hours: u64, // 密钥轮换周期（小时）
    clients: Vec<ClientConfig>,
}

/// 内部维护的 RSA 密钥对信息
struct ServerKeys {
    private_key: RsaPrivateKey,
    public_key_pem: String,
    kid: String, // JWT 需要的 Key ID
}

/// 授权码 (Code) 对应的会话信息
struct AuthSession {
    username: String,
    client_id: String,
}

struct AppState {
    config: AppConfig,
    http_client: reqwest::Client,
    keys: RwLock<Arc<ServerKeys>>, // 使用读写锁支持动态热更新密钥
    code_store: Mutex<HashMap<String, AuthSession>>, // 存储生成的临时 Code
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,    // 前端 RSA 加密后的 base64
    password: String,    // 前端 RSA 加密后的 base64
    client_id: String,   // AList 等客户端的 ID
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

// --- 进才教育网关逻辑 (硬编码，不随本地密钥轮换) ---

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
    let resp = client.get("https://www.jincai.sh.cn/zlineauthrize/xlogin")
        .header("User-Agent", "Mozilla/5.0").send().await.map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|_| "UTF8 Error".to_string())?;
    let id_pos = text.find("id=\"XToken\"").ok_or("XToken 标签未找到")?;
    let start = text[..id_pos].rfind('<').ok_or("标签起始缺失")?;
    let end = text[id_pos..].find('>').ok_or("标签结束缺失")? + id_pos;
    let tag = &text[start..=end];
    tag.split("value=\"").nth(1).and_then(|v| v.split('\"').next()).map(|v| v.to_string()).ok_or("XToken Value 缺失".into())
}

// --- 密钥管理逻辑 ---

/// 生成全新的 RSA 2048 位密钥对
fn generate_new_keys() -> ServerKeys {
    let mut rng = thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA 密钥生成失败");
    let pub_key_pem = priv_key.to_public_key().to_public_key_pem(LineEnding::LF).unwrap();
    ServerKeys {
        private_key: priv_key,
        public_key_pem: pub_key_pem,
        kid: Uuid::new_v4().to_string(), // 每次轮换生成新的密钥 ID
    }
}

/// 后台异步循环：定期更换密钥
async fn key_rotation_task(state: Arc<AppState>) {
    let interval = Duration::from_secs(state.config.key_rotation_hours * 3600);
    loop {
        tokio::time::sleep(interval).await;
        println!("[系统] 正在轮换本地 OIDC/网页加密密钥...");
        let new_keys = Arc::new(generate_new_keys());
        {
            let mut w = state.keys.write().unwrap();
            *w = new_keys;
        }
        println!("[完成] 密钥已更新，新 KID: {}", state.keys.read().unwrap().kid);
    }
}

// --- Axum 路由处理器 ---

/// OIDC 标准配置接口
async fn oidc_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "issuer": state.config.issuer,
        "authorization_endpoint": format!("{}/index.html", state.config.issuer),
        "token_endpoint": format!("{}/auth/token", state.config.issuer),
        "jwks_uri": format!("{}/auth/jwks", state.config.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

/// JWKS 接口：返回当前有效的公钥供 AList 校验 JWT 签名
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

/// 登录接口：验证进才账号并生成授权码
async fn login_handler(State(state): State<Arc<AppState>>, Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    // 检查 ClientID 是否在白名单
    if !state.config.clients.iter().any(|c| c.client_id == payload.client_id) {
        return (StatusCode::BAD_REQUEST, "无效的 Client ID").into_response();
    }

    // 获取当前私钥进行解密 (前端用的是轮换中的公钥)
    let current_keys = state.keys.read().unwrap().clone();
    let dec_user_res = general_purpose::STANDARD.decode(&payload.username)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Base64 解码用户名失败"));
    let dec_pass_res = general_purpose::STANDARD.decode(&payload.password)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Base64 解码密码失败"));

    let (dec_user_bytes, dec_pass_bytes) = match (dec_user_res, dec_pass_res) {
        (Ok(u), Ok(p)) => (u, p),
        (Err(e), _) | (_, Err(e)) => return e.into_response(),
    };

    let user = String::from_utf8(current_keys.private_key.decrypt(Pkcs1v15Encrypt, &dec_user_bytes).unwrap_or_default()).unwrap_or_default();
    let pass = String::from_utf8(current_keys.private_key.decrypt(Pkcs1v15Encrypt, &dec_pass_bytes).unwrap_or_default()).unwrap_or_default();

    // 进才网关交互
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
            state.code_store.lock().unwrap().insert(code.clone(), AuthSession {
                username: user,
                client_id: payload.client_id,
            });
            return Json(json!({ "code": code, "redirect_uri": payload.redirect_uri, "state": payload.state })).into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, Json(json!({"message": "进才身份验证失败"}))).into_response()
}

/// Token 兑换接口：用授权码换取 JWT
async fn token_exchange_handler(
    State(state): State<Arc<AppState>>, 
    Form(payload): Form<TokenExchangeRequest>
) -> impl IntoResponse {
    // 验证客户端凭据
    let is_valid_client = state.config.clients.iter()
        .any(|c| c.client_id == payload.client_id && c.client_secret == payload.client_secret);
    
    if !is_valid_client {
        return (StatusCode::UNAUTHORIZED, "客户端凭据错误").into_response();
    }

    let mut store = state.code_store.lock().unwrap();
    if let Some(session) = store.remove(&payload.code) {
        if session.client_id != payload.client_id {
            return (StatusCode::UNAUTHORIZED, "Code 不属于该客户端").into_response();
        }

        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: state.config.issuer.clone(),
            sub: session.username,
            aud: payload.client_id, 
            iat: now,
            exp: now + 3600 
        };

        // 使用当前有效的私钥签名 JWT
        let current_keys = state.keys.read().unwrap().clone();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(current_keys.kid.clone());
        
        let private_key_pem = current_keys.private_key.to_pkcs8_pem(LineEnding::LF).expect("私钥导出错误");
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("编码密钥创建失败");

        let token = encode(&header, &claims, &encoding_key).unwrap();

        return (StatusCode::OK, Json(json!({
            "id_token": token,
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600
        }))).into_response();
    }
    (StatusCode::UNAUTHORIZED, "授权码无效或已过期").into_response()
}

/// 提供当前公钥给前端网页，用于登录信息加密
async fn get_provider_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.keys.read().unwrap().clone();
    Json(json!({ "pub_key": keys.public_key_pem }))
}

// --- 主程序 ---

#[tokio::main]
async fn main() {
    // 1. 加载配置
    let config_str = fs::read_to_string("config.json").expect("无法读取 config.json");
    let config: AppConfig = serde_json::from_str(&config_str).expect("config.json 格式错误");

    // 2. 初始化密钥
    let initial_keys = Arc::new(generate_new_keys());

    let state = Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder().cookie_store(true).build().unwrap(),
        keys: RwLock::new(initial_keys),
        code_store: Mutex::new(HashMap::new()),
    });

    // 3. 启动密钥轮换后台任务
    let rotation_state = Arc::clone(&state);
    tokio::spawn(async move {
        key_rotation_task(rotation_state).await;
    });

    // 4. 构建路由
    let app = Router::new()
        .fallback_service(ServeDir::new("static")) // 存放 index.html
        .route("/.well-known/openid-configuration", get(oidc_config))
        .route("/auth/jwks", get(jwks_handler))
        .route("/auth/provider-key", get(get_provider_key))
        .route("/auth/login", post(login_handler))
        .route("/auth/token", post(token_exchange_handler))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods([Method::GET, Method::POST]).allow_headers(Any))
        .with_state(state);

    // 5. 启动服务
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("[启动] OIDC 服务已运行在 http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}