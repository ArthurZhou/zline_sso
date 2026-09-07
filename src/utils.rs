//! 通用工具函数
//!
//! 包含角色/标签字符串处理、redirect_uri 匹配、加密负载解密、
//! 会话 Cookie 构建以及若干小的安全辅助函数。

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use axum_extra::extract::cookie::Cookie;
use base64::{Engine, engine::general_purpose};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::state::AppState;

// ============ 角色 / 标签 ============

/// 校验并规范化角色字符串（逗号分隔的多角色）。
///
/// 每个角色只能包含 ASCII 字母、数字、连字符 `-` 与下划线 `_`，
/// 且自动去除重复项与空白。返回规范化后的逗号分隔字符串。
pub fn validate_role_str(role: &str) -> Result<String, String> {
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
pub fn parse_roles(role: &str) -> Vec<String> {
    role.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 判断角色字符串中是否包含指定角色。
pub fn has_role(role: &str, target: &str) -> bool {
    parse_roles(role).iter().any(|r| r == target)
}

/// 向角色字符串中添加一个标签（若已存在则保持不变）。
pub fn add_tag_to_role(role: &str, tag: &str) -> String {
    let mut roles = parse_roles(role);
    if !roles.iter().any(|r| r == tag) {
        roles.push(tag.to_string());
    }
    roles.join(",")
}

/// 从角色字符串中移除一个标签（若不存在则保持不变）。
pub fn remove_tag_from_role(role: &str, tag: &str) -> String {
    parse_roles(role)
        .into_iter()
        .filter(|r| r != tag)
        .collect::<Vec<_>>()
        .join(",")
}

// ============ OAuth / 安全 ============

/// 判断给定的 redirect_uri 是否与配置中的某个条目匹配。
///
/// - 若配置条目为纯字面量（不含正则元字符），则进行精确字符串比较（保持严格与向后兼容）；
/// - 否则将其作为正则表达式进行匹配，便于配置诸如 `^http://localhost:\d+/callback$` 的灵活规则。
pub fn redirect_matches(pattern: &str, uri: &str) -> bool {
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
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// 计算字符串的 SHA-256 摘要，以十六进制字符串形式返回。
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// 从请求头中提取客户端 IP 地址
/// 优先级：X-Forwarded-For -> X-Real-IP -> 连接地址
pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    socket_addr: Option<SocketAddr>,
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
pub fn decrypt_frontend_payload(
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
/// - `state`: 应用状态（用于读取路由前缀）
/// - `session_id`: 会话ID，作为Cookie的值存储
/// - `remember`: 是否记住登录状态
///   - `true`: Cookie有效期为7天
///   - `false`: Cookie为会话Cookie，浏览器关闭时过期
pub fn create_sso_cookie(state: &AppState, session_id: String, remember: bool) -> Cookie<'static> {
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
