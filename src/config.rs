//! 配置文件解析
//!
//! 从 `config.toml` 读取服务配置。每个 OIDC 客户端支持可选的
//! `friendly_name` 字段，用于在登录页 / 继续页向用户展示
//! “正在登录到哪个服务”。

use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub issuer: String,
    pub auth_path_prefix: String,
    pub rate_limit: RateLimitConfig,
    pub login_record_window: i32,
    pub geoip_mmdb_path: String,
    pub frontend_crypto: CryptoConfig,
    pub account_lockout: AccountLockoutConfig,
    pub cors_allowed_origins: Vec<String>,
    pub admin: AdminConfig,
    pub clients: Vec<ClientConfig>,
}

#[derive(Deserialize, Clone)]
pub struct AdminConfig {
    pub username: String,
    pub password_hash: String,
}

#[derive(Deserialize, Clone)]
pub struct RateLimitConfig {
    pub per_second: u64,
}

#[derive(Deserialize, Clone)]
pub struct CryptoConfig {
    pub shared_key: String,
    pub max_clock_skew_secs: i64,
}

#[derive(Deserialize, Clone)]
pub struct AccountLockoutConfig {
    pub failed_attempts_threshold: i32,
    pub lockout_duration_minutes: i32,
}

#[derive(Deserialize, Clone)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub return_extra_userinfo: Vec<String>,
    /// 客户端显示名称，展示在登录页 / 继续页的“正在登录到”区域。
    /// 缺省时回退为 `client_id`。
    #[serde(default)]
    pub friendly_name: Option<String>,
}

impl ClientConfig {
    /// 用于页面展示的名称：优先 `friendly_name`，缺省回退为 `client_id`。
    pub fn display_name(&self) -> String {
        self.friendly_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| self.client_id.clone())
    }
}

/// 读取并规范化配置文件。
///
/// 规范化内容：
/// - 去除 `issuer` 末尾多余的 `/`；
/// - 配置了 `auth_path_prefix` 时，issuer 追加该前缀，
///   保证 issuer 与各端点路径一致（OIDC 规范要求）。
pub fn load_config(path: &str) -> Config {
    let config_str = std::fs::read_to_string(path).expect("config.toml not found");
    let mut config: Config = toml::from_str(&config_str).expect("Failed to parse config.toml");

    if config.issuer.ends_with('/') {
        config.issuer.pop();
    }
    if !config.auth_path_prefix.is_empty() && !config.issuer.ends_with(&config.auth_path_prefix) {
        config.issuer = format!("{}{}", config.issuer, config.auth_path_prefix);
    }

    config
}
