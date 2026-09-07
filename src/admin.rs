//! 管理员 API 处理器
//!
//! 用户管理（列表/添加/删除/角色）、登录日志查询，
//! 以及账户状态设置（正常 / 受限 / 锁定 / 跳过验证）。

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::format_local_time;
use crate::db;
use crate::models::UserState;
use crate::state::AppState;
use crate::utils::validate_role_str;

/// 从会话 Cookie 校验管理员身份。
///
/// 仅当会话是通过管理员密码验证登录（`is_admin == true`）时才放行，
/// 返回管理员用户名；否则返回对应的 HTTP 错误响应。
pub fn require_admin(state: &Arc<AppState>, jar: &CookieJar) -> Result<String, Response> {
    let session_id = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "未登录"})),
            )
                .into_response());
        }
    };

    let (username, is_admin) = {
        let store = state.session_store.lock().unwrap();
        match store.get(&session_id) {
            Some(s) => (s.username.clone(), s.is_admin),
            None => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "会话无效或已过期"})),
                )
                    .into_response());
            }
        }
    };

    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "需要管理员权限"})),
        )
            .into_response());
    }

    Ok(username)
}

/// 管理员设置角色请求
#[derive(Deserialize)]
pub struct AdminRoleRequest {
    pub role: String,
}

/// 管理员封禁请求
#[derive(Deserialize)]
pub struct AdminBanRequest {
    pub reason: Option<String>,
    /// 封禁时长（小时），缺省/为 0 时表示永久封禁
    pub duration_hours: Option<i64>,
}

/// 管理员设置账户状态请求
///
/// `state`：0=正常, 1=受限（可登录个人中心）, 2=锁定（完全禁止登录）, 3=跳过外部验证
#[derive(Deserialize)]
pub struct AdminStateRequest {
    pub state: i32,
    pub reason: Option<String>,
    /// 限制时长（小时），仅对受限/锁定有效，0/缺省表示直到手动解除
    pub duration_hours: Option<i64>,
}

/// 管理员添加用户请求
#[derive(Deserialize)]
pub struct AdminAddUserRequest {
    pub username: String,
    /// 初始角色/标签（逗号分隔，可缺省，缺省为 "user"）
    pub role: Option<String>,
    pub full_name: Option<String>,
}

/// 查询用户列表（管理员）。
///
/// Query 参数：`keyword`（用户名/姓名/外部ID 模糊搜索）、`limit`、`offset`（分页）。
pub async fn admin_users_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let keyword = params.get("keyword").cloned().unwrap_or_default();
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let users = match db::list_users(&conn, &keyword, limit, offset) {
        Ok(u) => u,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let list: Vec<_> = users
        .iter()
        .map(|u| {
            json!({
                "uid": u.uid,
                "username": u.username,
                "role": u.role,
                "external_uid": u.external_uid,
                "full_name": u.full_name,
                "student_id": u.student_id,
                "gender": u.gender,
                "flag": u.flag,
                "state": u.state,
                "state_description": u.state_description,
                "restriction_end_time": u.restriction_end_time,
                "last_login_time": u.last_login_time,
                "failed_attempts": u.failed_attempts,
            })
        })
        .collect();

    Json(json!({ "users": list })).into_response()
}

/// 查询全量登录日志（管理员，跨所有用户）。
///
/// Query 参数：`keyword`（按用户名过滤）、`limit`、`offset`（分页）。
pub async fn admin_logs_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let keyword = params.get("keyword").cloned().unwrap_or_default();
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let logs = match db::list_all_login_logs(&conn, &keyword, limit, offset) {
        Ok(l) => l,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    Json(json!({ "logs": logs })).into_response()
}

/// 计算限制结束时间戳与状态描述。
///
/// `duration_hours` 为 0/缺省时表示无固定结束时间（返回 0）。
fn build_restriction(reason: &str, duration_hours: Option<i64>, permanent_label: &str) -> (String, i64) {
    match duration_hours {
        Some(h) if h > 0 => {
            let end_ts = chrono::Utc::now().timestamp() + h * 3600;
            (
                format!("{}，解封时间 {}", reason, format_local_time(end_ts)),
                end_ts,
            )
        }
        _ => (format!("{}（{}）", reason, permanent_label), 0),
    }
}

/// 设置用户账户状态（管理员）。
///
/// Body：`{ "state": 0|1|2|3, "reason": 可选说明, "duration_hours": 可选限制时长（小时） }`。
///
/// - `0` 正常：清除状态描述与结束时间；
/// - `1` 受限：允许登录个人中心，不允许 OAuth 授权；
/// - `2` 锁定：完全禁止登录（等价于原来的封禁）；
/// - `3` 跳过验证：登录时跳过进才外部验证。
pub async fn admin_set_state_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
    Json(payload): Json<AdminStateRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let user_state = match payload.state {
        0 => UserState::Normal,
        1 => UserState::Restricted,
        2 => UserState::Locked,
        3 => UserState::BypassExternal,
        _ => {
            return Json(json!({"error": "无效的状态值，允许：0=正常, 1=受限, 2=锁定, 3=跳过验证"}))
                .into_response();
        }
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    let (description, end_ts) = match user_state {
        UserState::Normal | UserState::BypassExternal => (String::new(), 0),
        UserState::Restricted => build_restriction(
            &payload.reason.unwrap_or_else(|| "管理员限制".to_string()),
            payload.duration_hours,
            "长期限制",
        ),
        UserState::Locked => build_restriction(
            &payload.reason.unwrap_or_else(|| "管理员封禁".to_string()),
            payload.duration_hours,
            "永久封禁",
        ),
    };

    if let Err(_) = db::set_user_state(&conn, &user_info.uid, user_state, &description, end_ts) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    let mut message = format!("已将 {} 的状态设置为 {}", username, user_state.display_name());
    if !description.is_empty() {
        message.push_str(&format!("（{}）", description));
    }

    Json(json!({ "success": true, "message": message })).into_response()
}

/// 封禁用户（管理员）。
///
/// Body：`{ "reason": 可选原因, "duration_hours": 可选封禁时长（小时），0/缺省为永久 }`。
/// 等价于 `POST .../state` 且 `state = 2`，保留以兼容旧客户端。
pub async fn admin_ban_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
    Json(payload): Json<AdminBanRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    let reason = payload.reason.unwrap_or_else(|| "管理员封禁".to_string());
    let (description, end_ts) = build_restriction(&reason, payload.duration_hours, "永久封禁");

    if let Err(_) = db::set_user_state(&conn, &user_info.uid, UserState::Locked, &description, end_ts)
    {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已封禁用户 {}", username) })).into_response()
}

/// 解封用户（管理员）。
pub async fn admin_unban_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    if let Err(_) = db::set_user_state(&conn, &user_info.uid, UserState::Normal, "", 0) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已解封用户 {}", username) })).into_response()
}

/// 设置用户角色（管理员）。
///
/// Body：`{ "role": "user" | "admin" | "staff" | "tag-a,tag-b" | ... }`。
/// 支持逗号分隔的多个角色，每个角色仅允许字母、数字、连字符与下划线。
pub async fn admin_role_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
    Json(payload): Json<AdminRoleRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let role = payload.role.trim().to_string();
    if role.is_empty() {
        return Json(json!({"error": "角色不能为空"})).into_response();
    }
    // 校验角色格式：逗号分隔的多角色，每个仅允许字母/数字/-/_，并规范化
    let role = match validate_role_str(&role) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return Json(json!({"error": "角色不能为空"})).into_response(),
        Err(e) => return Json(json!({"error": e})).into_response(),
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    if let Err(_) = db::set_user_role(&conn, &user_info.uid, &role) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已将 {} 的角色设置为 {}", username, role) }))
        .into_response()
}

/// 添加用户（管理员）。
///
/// Body：`{ "username": 必填, "role": 可选（默认 "user"）, "full_name": 可选 }`。
pub async fn admin_add_user_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<AdminAddUserRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let username = payload.username.trim().to_string();
    if username.is_empty() {
        return Json(json!({"error": "用户名不能为空"})).into_response();
    }

    // 初始角色：缺省为 "user"，否则校验格式
    let role = match payload.role {
        Some(r) => match validate_role_str(&r) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => "user".to_string(),
            Err(e) => return Json(json!({"error": e})).into_response(),
        },
        None => "user".to_string(),
    };

    let full_name = payload.full_name.unwrap_or_default().trim().to_string();

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    if let Ok(Some(_)) = db::get_user_full_info(&conn, &username) {
        return Json(json!({"error": "用户已存在"})).into_response();
    }

    if let Err(_) = db::add_user(&conn, &username, &role, &full_name) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已添加用户 {}（角色：{}）", username, role) }))
        .into_response()
}

/// 删除用户（管理员）。
pub async fn admin_delete_user_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(username): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&state, &jar) {
        return resp;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let exists = db::get_user_full_info(&conn, &username)
        .map(|o| o.is_some())
        .unwrap_or(false);
    if !exists {
        return Json(json!({"error": "用户不存在"})).into_response();
    }

    if let Err(_) = db::delete_user(&conn, &username) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({ "success": true, "message": format!("已删除用户 {}", username) })).into_response()
}
