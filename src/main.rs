//! zline SSO 服务入口
//!
//! 本文件仅负责：模块声明、应用状态初始化、路由装配与服务启动。
//! 业务逻辑分布在各子模块中：
//!
//! - `config`   ：配置文件解析
//! - `models`   ：核心数据模型与常量
//! - `state`    ：全局应用状态
//! - `utils`    ：通用工具函数
//! - `auth`     ：登录 / 继续授权 / 登出
//! - `oidc`     ：OIDC 端点（token / userinfo / jwks / discovery / client-info）
//! - `admin`    ：管理员 API
//! - `tags`     ：员工标签管理
//! - `profile`  ：个人中心 API
//! - `statics`  ：静态页面
//! - `db`       ：数据库访问
//! - `zline`    ：进才（zline）外部认证封装

mod admin;
mod auth;
mod config;
mod db;
mod models;
mod oidc;
mod profile;
mod state;
mod statics;
mod tags;
mod utils;
mod zline;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::{
    Router,
    http::header::HeaderValue,
    response::Redirect,
    routing::{get, post},
};
use maxminddb::Reader;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;

fn init_app_state(config: config::Config) -> Arc<AppState> {
    let db_path = "users.db".to_string();
    db::init_db(&db_path).expect("Failed to init database");

    let manager = r2d2_sqlite::SqliteConnectionManager::file(&db_path);
    let db_pool = r2d2::Pool::new(manager).expect("Failed to create database pool");

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let kid = Uuid::new_v4().to_string();

    let geoip_reader = match Reader::open_readfile(&config.geoip_mmdb_path) {
        Ok(reader) => Some(Arc::new(reader)),
        Err(err) => {
            warn!(
                path = %config.geoip_mmdb_path, error = %err,
                "无法打开 GeoIP MMDB 文件，地理位置信息将不可用"
            );
            None
        }
    };

    Arc::new(AppState {
        config: config.clone(),
        http_client: reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap(),
        keys: RwLock::new(Arc::new((private_key, kid))),
        code_store: Mutex::new(HashMap::new()),
        session_store: Mutex::new(HashMap::new()),
        db_pool,
        geoip_reader,
        geoip_cache: Mutex::new(HashMap::new()),
    })
}

#[tokio::main]
async fn main() {
    // 初始化结构化日志：级别可通过 RUST_LOG 环境变量覆盖（默认 info）
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config = config::load_config("config.toml");
    info!(issuer = %config.issuer, host = %config.host, port = config.port,
        "配置文件加载完成");

    // 预加载 students CSV 到内存缓存
    if let Err(e) = zline::load_csv_cache("students_data.csv") {
        warn!("failed to load students_data.csv: {}", e);
    }

    let state = init_app_state(config.clone());
    let prefix = state.config.auth_path_prefix.clone();

    // 仅允许已注册客户端来源的 CORS（由配置的 cors_allowed_origins 指定）
    let allowed_origins: Vec<HeaderValue> = state
        .config
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    // 定期清理过期会话/授权码/GeoIP 缓存，防止内存无界增长
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                state.cleanup_expired();
            }
        });
    }

    // 速率限制配置
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(state.config.rate_limit.per_second as u32)
            .key_extractor(PeerIpKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );

    // 1. 构造受 prefix 影响的业务路由
    let auth_router = Router::new()
        .route("/", get(statics::login_page_handler)) // 对应 {prefix}/
        .route("/crypto-config", get(oidc::crypto_config_handler))
        // 客户端信息：登录页/继续页加载时展示“正在登录到”并预校验 client 配置
        .route("/client-info", get(oidc::client_info_handler))
        .route("/agreement", get(statics::agreement_html_handler))
        .route("/agreement.md", get(statics::agreement_md_handler))
        .route("/login", post(auth::login_handler))
        .route("/continue", get(auth::continue_handler))
        .route("/logout", get(auth::logout_handler))
        .route("/profile", get(statics::profile_page_handler))
        .route("/profile/api", get(profile::profile_api_handler))
        .route("/profile/tags", get(tags::profile_tags_handler))
        .route("/profile/tags/users", get(tags::profile_tag_users_handler))
        .route("/profile/tags/add", post(tags::profile_tag_add_handler))
        .route(
            "/profile/tags/remove",
            post(tags::profile_tag_remove_handler),
        )
        .route("/token", post(oidc::token_exchange_handler))
        .route("/userinfo", get(oidc::userinfo_handler))
        .route("/jwks", get(oidc::jwks_handler));

    // 2. 构造主路由
    let app = Router::new()
        // 根目录直接跳转到 prefix/
        .route(
            "/",
            get({
                let p = prefix.clone();
                move || {
                    let path = format!("{p}");
                    async move { Redirect::temporary(&path) }
                }
            }),
        )
        // 使用 nest 挂载业务路由
        // Axum 的 nest 在路径不带斜杠时只匹配 {prefix}（不匹配 {prefix}/），
        // 因此这里显式补充 {prefix}/ 路由，使两种写法都能访问登录页。
        .route(&format!("{prefix}/"), get(statics::login_page_handler))
        .nest(&prefix, auth_router)
        // 管理员 API（放在主路由、显式带 prefix）
        .route(
            &format!("{prefix}/admin/api/users"),
            get(admin::admin_users_handler).post(admin::admin_add_user_handler),
        )
        .route(
            &format!("{prefix}/admin/api/logs"),
            get(admin::admin_logs_handler),
        )
        // 账户状态设置（正常/受限/锁定/跳过验证）
        .route(
            &format!("{prefix}/admin/api/users/:username/state"),
            post(admin::admin_set_state_handler),
        )
        // 以下两个保留以兼容旧客户端（等价于 state=2 / state=0）
        .route(
            &format!("{prefix}/admin/api/users/:username/ban"),
            post(admin::admin_ban_handler),
        )
        .route(
            &format!("{prefix}/admin/api/users/:username/unban"),
            post(admin::admin_unban_handler),
        )
        .route(
            &format!("{prefix}/admin/api/users/:username/role"),
            post(admin::admin_role_handler),
        )
        .route(
            &format!("{prefix}/admin/api/users/:username/delete"),
            post(admin::admin_delete_user_handler),
        )
        // 固定路径不受 nest 影响（根路径 discovery，向后兼容）
        .route(
            "/.well-known/openid-configuration",
            get(oidc::oidc_config_handler),
        );

    // OIDC discovery 必须挂在 issuer 路径下：issuer 已含 prefix（如 /sso）
    // 时，{prefix}/.well-known/openid-configuration 也必须可达，否则客户端
    // 按 issuer 拉取 discovery 会 404。prefix 为空时与根路由重复，跳过。
    let app = if prefix.is_empty() {
        app
    } else {
        app.route(
            &format!("{prefix}/.well-known/openid-configuration"),
            get(oidc::oidc_config_handler),
        )
    };

    let app = app
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(allowed_origins)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST]),
        )
        // 请求级访问日志（method、uri、状态码、耗时）
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!(%addr, "服务启动");
    info!("服务运行在 http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
