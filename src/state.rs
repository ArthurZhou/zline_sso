//! 全局应用状态
//!
//! 持有配置、HTTP 客户端、RSA 密钥、会话/授权码存储、数据库连接池
//! 与 GeoIP 查询器，并提供地理位置解析与过期数据清理逻辑。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use maxminddb::Reader;

use crate::config::Config;
use crate::db;
use crate::models::{AuthSession, SessionData, GEOIP_CACHE_MAX};
use crate::utils::{constant_time_eq, sha256_hex};

#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country: String,
    pub region: String,
}

pub struct AppState {
    pub config: Config,
    pub http_client: reqwest::Client,
    pub keys: RwLock<Arc<(rsa::RsaPrivateKey, String)>>,
    pub code_store: Mutex<HashMap<String, AuthSession>>,
    pub session_store: Mutex<HashMap<String, SessionData>>,
    pub db_pool: db::DbPool,
    pub geoip_reader: Option<Arc<Reader<Vec<u8>>>>,
    pub geoip_cache: Mutex<HashMap<String, GeoLocation>>,
}

impl AppState {
    pub fn lookup_geo_location(&self, ip: &str) -> GeoLocation {
        if ip == "-1" {
            return GeoLocation {
                country: "未知".to_string(),
                region: "未知".to_string(),
            };
        }

        if let Some(location) = self.geoip_cache.lock().unwrap().get(ip) {
            return location.clone();
        }

        let location = self.resolve_geo_location(ip);
        self.geoip_cache
            .lock()
            .unwrap()
            .insert(ip.to_string(), location.clone());
        location
    }

    fn resolve_geo_location(&self, ip: &str) -> GeoLocation {
        let default_unknown = GeoLocation {
            country: "未知".to_string(),
            region: "未知".to_string(),
        };

        let lan_location = GeoLocation {
            country: "局域网".to_string(),
            region: "局域网".to_string(),
        };

        // 1. 解析 IP 字符串
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return default_unknown,
        };

        // 2. 识别内网/私有地址
        if AppState::is_lan(ip_addr) {
            return lan_location;
        }

        // 3. 检查 Reader 是否可用
        let reader = match self.geoip_reader.as_ref() {
            Some(reader) => reader,
            None => return default_unknown,
        };

        // 4. 查询 MMDB
        let data: serde_json::Value = match reader.lookup(ip_addr) {
            Ok(d) => d,
            Err(_) => return default_unknown,
        };

        // 5. 提取国家 (优先中文)
        let country = data
            .get("country")
            .and_then(|c| c.get("names"))
            .or_else(|| data.get("registered_country").and_then(|rc| rc.get("names")))
            .and_then(|n| n.get("zh-CN").or(n.get("en")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "未知".to_string());

        // 6. 提取地区 (优先中文)
        let region = data
            .get("subdivisions")
            .and_then(|s| s.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("names"))
            .or_else(|| data.get("city").and_then(|c| c.get("names")))
            .and_then(|n| n.get("zh-CN").or(n.get("en")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "未知".to_string());

        GeoLocation { country, region }
    }

    /// 辅助函数：判断 IP 是否属于局域网或保留地址
    pub fn is_lan(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || // 127.0.0.1
                v4.is_private() ||  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                v4.is_link_local() // 169.254.0.0/16
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || // ::1
                // 检查是否为唯一本地地址 (fc00::/7) 或 链路本地地址 (fe80::/10)
                (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// 定期清理过期的会话、授权码与过大的 GeoIP 缓存，防止内存无界增长。
    pub fn cleanup_expired(&self) {
        self.session_store
            .lock()
            .unwrap()
            .retain(|_, s| s.created_at.elapsed().map(|d| d < crate::models::SESSION_TTL).unwrap_or(true));

        self.code_store.lock().unwrap().retain(|_, c| {
            c.created_at
                .elapsed()
                .map(|d| d < crate::models::CODE_TTL)
                .unwrap_or(true)
        });

        let mut geoip = self.geoip_cache.lock().unwrap();
        if geoip.len() > GEOIP_CACHE_MAX {
            geoip.clear();
        }
    }

    /// 判断给定用户名与密码是否为配置中的管理员账户。
    ///
    /// 该校验完全在本地完成（密码取 SHA-256 摘要后与配置中的摘要进行恒定时间比较），
    /// 因此管理员凭据绝不会被发送到外部（进才）系统验证。
    pub fn is_admin(&self, username: &str, password: &str) -> bool {
        if username != self.config.admin.username {
            return false;
        }
        let digest = sha256_hex(password);
        constant_time_eq(&digest, &self.config.admin.password_hash)
    }
}
