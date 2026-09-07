//! OIDC 端点处理器
//!
//! 包含 token 交换、userinfo、JWKS、OIDC discovery、
//! 前端加密配置下发，以及供登录页/继续页使用的客户端信息接口。

use axum::{
    Form, Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

use crate::db;
use crate::models::{Claims, IdTokenClaims, CODE_TTL};
use crate::state::AppState;
use crate::utils::{constant_time_eq, redirect_matches};

#[derive(Deserialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: String,
}

pub async fn token_exchange_handler(
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
        c.client_id == payload.client_id && constant_time_eq(&c.client_secret, &payload.client_secret)
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

pub async fn userinfo_handler(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap) -> Response {
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

            let (role, xuid, xuxm, student_id, gender) = match db::get_user_full_info(&conn, username)
            {
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

pub async fn jwks_handler(State(state): State<Arc<AppState>>) -> Response {
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

/// OIDC discovery。挂载在根路径和 {prefix} 两个位置（issuer 已含 prefix）。
pub async fn oidc_config_handler(State(state): State<Arc<AppState>>) -> Response {
    let issuer = &state.config.issuer;

    Json(json!({
        "issuer": issuer,
        // 本项目没有独立的 /authorize 端点：OAuth 授权参数
        // （client_id/redirect_uri/state/nonce）由登录页 {prefix}/ 的 JS
        // 从 query string 读取，登录成功后回跳 redirect_uri?code=...。
        // 因此 discovery 必须指向登录页本身，否则客户端（如 oneshare）
        // 按 /authorize 跳转会 404。
        "authorization_endpoint": format!("{issuer}/"),
        "token_endpoint": format!("{}/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "jwks_uri": format!("{}/jwks", issuer),
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
pub async fn crypto_config_handler(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({
        "shared_key": state.config.frontend_crypto.shared_key
    }))
    .into_response()
}

/// 客户端信息接口：供登录页 / 继续页在页面加载阶段展示
/// “正在登录到哪个服务”以及该服务将获得的用户信息字段，
/// 同时在页面加载阶段即校验 client 配置的合法性。
///
/// Query 参数：`client_id`（必填，空表示个人中心直接登录）、`redirect_uri`（可选）。
///
/// 校验失败（client_id 不存在或 redirect_uri 不匹配）时返回 400 与错误信息，
/// 前端据此立即展示错误而无需等到用户点击登录/继续。
pub async fn client_info_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let client_id = params.get("client_id").map(|s| s.trim()).unwrap_or("");

    // 不带 client_id：个人中心直接登录，无需展示客户端信息
    if client_id.is_empty() {
        return Json(json!({"direct_login": true})).into_response();
    }

    let client = match state.config.clients.iter().find(|c| c.client_id == client_id) {
        Some(c) => c,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error": "OAuth客户端ID错误"})),
            )
                .into_response();
        }
    };

    // 页面加载阶段即校验 redirect_uri（与 /login、/continue 处的校验保持一致，
    // 此处仅为提前反馈，API 侧校验仍然保留以防止攻击）
    if let Some(redirect_uri) = params.get("redirect_uri").map(|s| s.trim()).filter(|s| !s.is_empty())
    {
        let redirect_ok = client
            .redirect_uris
            .iter()
            .any(|pattern| redirect_matches(pattern, redirect_uri));
        if !redirect_ok {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error": "OAuth重定向URI错误"})),
            )
                .into_response();
        }
    }

    Json(json!({
        "client_id": client_id,
        "friendly_name": client.display_name(),
        "userinfo_fields": client.return_extra_userinfo,
    }))
    .into_response()
}
