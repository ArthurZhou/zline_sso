use axum::{
    Router, extract::State, http::HeaderMap, response::{IntoResponse, Json}, routing::{get, post}
};
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::services::ServeDir;

use rsa::{Pkcs1v15Encrypt, RsaPublicKey, traits::PublicKeyParts};
use rsa::pkcs8::DecodePublicKey;
use base64::{Engine as _, engine::general_purpose};

// The Public Key from your crypto.js file
const PUBLIC_KEY_B64: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCC0hrRIjb3noDWNtbDpANbjt5Iwu2NFeDwU16Ec87ToqeoIm2KI+cOs81JP9aTDk/jkAlU97mN8wZkEMDr5utAZtMVht7GLX33Wx9XjqxUsDfsGkqNL8dXJklWDu9Zh80Ui2Ug+340d5dZtKtd+nv09QZqGjdnSp9PTfFDBY133QIDAQAB"; // Replace with your FULL key from crypto.js

// --- Config ---
const JWT_SECRET: &[u8] = b"your_secret_key_32_chars_long_!!";

// --- Data Models ---
struct AppState {
    http_client: Client,
    db: SqlitePool,
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
    redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
struct UserIdentity {
    nickname: Option<String>,
    role: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    nickname: String,
    role: String,
    exp: usize,
}

// --- Database Auto-Init ---
async fn init_database() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:data.db?mode=rwc")
        .await
        .expect("Could not connect to data.db");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            nickname TEXT,
            role TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to initialize tables");

    // Pre-populate a test user
    sqlx::query("INSERT OR IGNORE INTO users (username, nickname, role) VALUES ('admin', 'System Admin', 'superuser')")
        .execute(&pool)
        .await
        .ok();

    pool
}

fn encrypt_request(data: HashMap<String, String>) -> Result<HashMap<String, String>, String> {
    // 1. Load the Public Key
    // JSEncrypt usually uses PKCS#1 or SubjectPublicKeyInfo (SPKI) format.
    // We parse it from the PEM-like base64 string.
    let pub_key_der = general_purpose::STANDARD
        .decode(PUBLIC_KEY_B64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    let public_key = RsaPublicKey::from_public_key_der(&pub_key_der)
        .map_err(|e| format!("RSA Public Key error: {}", e))?;

    let mut encrypted_data = HashMap::new();
    let mut rng = rand::thread_rng();

    // 2. Encrypt each field individually (matches your JS loop)
    for (key, value) in data {
        let padding = Pkcs1v15Encrypt;
        let enc_data = public_key
            .encrypt(&mut rng, padding, value.as_bytes())
            .map_err(|e| format!("Encryption error for {}: {}", key, e))?;

        // 3. Encode result to Base64
        let b64_encoded = general_purpose::STANDARD.encode(enc_data);
        encrypted_data.insert(key, b64_encoded);
    }

    Ok(encrypted_data)
}

async fn get_xtoken() -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://www.jincai.sh.cn/zlineauthrize/xlogin")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let text = resp.text().await.map_err(|_| "UTF8 Error".to_string())?;

    // 1. Locate the anchor (id="XToken")
    let id_marker = "id=\"XToken\"";
    let id_pos = text.find(id_marker).ok_or("XToken ID not found")?;

    // 2. Find the start of THIS specific tag (<) by looking backwards from the ID
    let tag_start = text[..id_pos].rfind('<').ok_or("Tag start not found")?;
    
    // 3. Find the end of THIS specific tag (>) by looking forwards from the ID
    let tag_end = text[id_pos..].find('>').ok_or("Tag end not found")? + id_pos;

    // 4. Extract the full tag string safely
    let full_tag = &text[tag_start..=tag_end];

    // 5. Catch the value field inside this isolated string
    let xtoken = full_tag
        .split("value=\"")
        .nth(1)
        .and_then(|v| v.split('\"').next())
        .ok_or("Value attribute not found within XToken tag")?;

    Ok(xtoken.to_string())
}

// --- Route Handlers ---
async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginPayload>,
) -> impl IntoResponse {
    // 1. Fetch dynamic XToken
    let xtoken = match get_xtoken().await {
        Ok(t) => t,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(json!({"message": e})),
            )
                .into_response();
        }
    };

    // 2. Verify with remote legacy system
    let mut data = HashMap::new();
    data.insert("XToken".to_string(), xtoken);
    data.insert("pzlusername".to_string(), payload.username.clone());
    data.insert("pzlpassword".to_string(), payload.password.clone());

    let encrypted_body = encrypt_request(data).expect("failed to encrypt");

    let resp = state
        .http_client
        .post("https://www.jincai.sh.cn/zlineauthrize/xlogin/sysxlogin")
        .form(&encrypted_body)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let res_json: Value = r.json().await.unwrap_or(json!({}));
            if res_json["succeed"] == "1" {
                // 3. Success! Now lookup local identity in data.db
                // Using non-macro query to avoid compile-time DATABASE_URL requirement
                let identity = sqlx::query_as::<_, UserIdentity>(
                    "SELECT nickname, role FROM users WHERE username = ?",
                )
                .bind(&payload.username)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();

                let nickname = identity
                    .as_ref()
                    .and_then(|i| i.nickname.clone())
                    .unwrap_or_else(|| "External User".into());
                let role = identity
                    .as_ref()
                    .and_then(|i| i.role.clone())
                    .unwrap_or_else(|| "guest".into());

                // 4. Generate JWT
                let claims = Claims {
                    sub: payload.username,
                    nickname,
                    role,
                    exp: 2000000000, // Year 2033
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(JWT_SECRET),
                )
                .unwrap();

                Json(json!({
                    "code": 200,
                    "id_token": token,
                    "status": "authenticated",
                    "redirect_uri": payload.redirect_uri.unwrap_or_else(|| "/".into()) // Return the target
                }))
                .into_response()
            } else {
                let err = res_json["errorMsg"]
                    .as_str()
                    .unwrap_or("Remote Auth Failed");
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(json!({"message": err})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": e.to_string()})),
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    // Initialize DB & Client
    let db = init_database().await;
    let http_client = Client::builder()
        .use_rustls_tls() // No OpenSSL dependency
        .build()
        .unwrap();

    let state = Arc::new(AppState { http_client, db });

    // Build App
    let app = Router::new()
        // Serve static files from /static directory
        .fallback_service(ServeDir::new("static"))
        .route("/auth/login", post(login_handler))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    println!("Server running at http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
