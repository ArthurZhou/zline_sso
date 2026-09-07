//! 核心数据模型与常量
//!
//! 包含会话/授权码、JWT 声明以及用户状态/标记枚举。

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// 会话有效期：7 天
pub const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// 授权码有效期：5 分钟
pub const CODE_TTL: Duration = Duration::from_secs(300);
/// GeoIP 缓存最大条目数
pub const GEOIP_CACHE_MAX: usize = 10_000;

/// Access Token 声明（携带者令牌，用于 userinfo 端点）
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
}

/// ID Token 声明（OIDC 标准声明，必须包含 nonce 以绑定授权请求）
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub azp: Option<String>,
    pub exp: usize,
    pub iat: usize,
    pub auth_time: usize,
    pub nonce: Option<String>,
}

/// 一次 OAuth 授权请求的上下文（授权码 -> token 交换期间保存）
#[derive(Clone)]
pub struct AuthSession {
    pub username: String,
    pub client_id: String,
    pub nonce: Option<String>,
    pub created_at: SystemTime,
}

/// 登录会话数据
pub struct SessionData {
    pub username: String,
    /// 是否通过管理员密码验证登录（仅管理员密码命中时为 true）。
    /// 管理员用户名同时可能是普通进才账户，因此不能仅凭用户名判定管理员。
    pub is_admin: bool,
    #[allow(dead_code)]
    pub created_at: SystemTime,
}

/// 账户状态（个位数表示账户状态）
#[derive(PartialEq, Default, Debug, Clone, Copy)]
pub enum UserState {
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

impl UserState {
    /// 状态的中文名称。
    pub fn display_name(self) -> &'static str {
        match self {
            UserState::Normal => "正常",
            UserState::Restricted => "受限",
            UserState::Locked => "锁定",
            UserState::BypassExternal => "跳过验证",
        }
    }
}

/// 用户状态标记（个位数表示账户标记）
#[derive(PartialEq, Default)]
pub enum UserFlag {
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
