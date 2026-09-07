//! 员工（staff）标签管理处理器
//!
//! staff 用户可以为其自带的标签（不含 `user` / `staff` / `admin`）
//! 管理其他用户：查询已加标签的用户、添加标签、移除标签。
//!
//! 权限规则：
//! - 仅普通（非管理员会话）登录且角色包含 `staff` 的用户可用；
//! - 只能操作自己自带的标签；
//! - 不能对自己操作；
//! - 同组其他带 `staff` 标签的用户**可见但不可操作**（不能增删其标签）；
//! - 同组带 `admin` 标签的用户（同组管理员）**可见但不可操作**（不能增删其标签）。

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::db;
use crate::state::AppState;
use crate::utils::{add_tag_to_role, has_role, parse_roles, remove_tag_from_role};

/// 员工（staff）标签管理请求
///
/// 用于为其他用户添加 / 移除标签。
#[derive(Deserialize)]
pub struct TagManageRequest {
    pub username: String,
    pub tag: String,
    /// 目标用户姓名（添加标签时用于确认用户身份，防止误加到他人）
    pub full_name: Option<String>,
}

/// 从会话 Cookie 校验登录身份。
///
/// 返回 `(用户名, 是否为管理员会话)`；未登录或会话失效时返回对应的 HTTP 错误响应。
pub fn require_session(
    state: &Arc<AppState>,
    jar: &CookieJar,
) -> Result<(String, bool), Response> {
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

    let store = state.session_store.lock().unwrap();
    match store.get(&session_id) {
        Some(s) => Ok((s.username.clone(), s.is_admin)),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "会话无效或已过期"})),
        )
            .into_response()),
    }
}

/// 校验当前会话是否为可进行标签管理的 staff 用户。
///
/// 仅当会话为普通（非管理员）登录，且当前用户的角色包含 `staff` 时放行，
/// 返回 `(用户名, 可管理标签列表)`。可管理标签 = 当前用户自带的标签
/// （不含基线角色 `user` 与提权风险角色 `staff` / `admin`）。
pub fn require_tag_manager(
    state: &Arc<AppState>,
    jar: &CookieJar,
) -> Result<(String, Vec<String>), Response> {
    let (username, is_admin) = match require_session(state, jar) {
        Ok(v) => v,
        Err(r) => return Err(r),
    };
    if is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "管理员会话不支持标签管理"})),
        )
            .into_response());
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "内部错误"})),
            )
                .into_response());
        }
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({"error": "用户不存在"})),
            )
                .into_response());
        }
    };

    let roles = parse_roles(&user_info.role);
    if !roles.iter().any(|r| r == "staff") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "需要 staff 标签权限"})),
        )
            .into_response());
    }

    let manageable: Vec<String> = roles
        .into_iter()
        .filter(|r| r != "staff" && r != "admin" && r != "user")
        .collect();
    Ok((username, manageable))
}

/// 获取当前用户（staff）可管理的标签信息。
///
/// 返回 `{ can_manage, staff, role, manageable_tags }`。
/// 用于前端判断是否展示标签管理界面。
pub async fn profile_tags_handler(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let (username, is_admin) = match require_session(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let user_info = match db::get_user_full_info(&conn, &username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let roles = parse_roles(&user_info.role);
    let is_staff = roles.iter().any(|r| r == "staff");
    let manageable_tags: Vec<String> = roles
        .into_iter()
        .filter(|r| r != "staff" && r != "admin" && r != "user")
        .collect();

    Json(json!({
        "can_manage": is_staff && !is_admin,
        "staff": is_staff,
        "role": user_info.role,
        "manageable_tags": manageable_tags,
    }))
    .into_response()
}

/// 员工标签管理：查询已加标签的用户列表（仅 staff 用户可用）。
///
/// 返回与当前 staff 共享至少一个可管理标签的用户：
/// - **包含同组其他 staff 用户**（带 `staff` 标签且共享组标签的用户），
///   其条目带 `is_staff: true` 标记，前端据此隐藏操作按钮；
/// - **包含同组管理员**（带 `admin` 标签且共享组标签的用户），
///   其条目带 `is_admin: true` 标记，前端据此隐藏操作按钮；
/// - 仅暴露该 staff 可管理的标签（与其自带标签求交集），避免泄露其无权查看的标签。
/// Query 参数：`keyword`、`limit`、`offset`。
pub async fn profile_tag_users_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let (_, manageable) = match require_tag_manager(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

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

    let users = match db::list_tagged_users(&conn, &keyword, &manageable, limit, offset) {
        Ok(u) => u,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let list: Vec<_> = users
        .iter()
        .map(|u| {
            // 仅暴露该 staff 可管理的标签：与自身标签求交集，
            // 避免泄露其无权查看的标签（如 tag-c）。
            let visible_tags: Vec<String> = parse_roles(&u.role)
                .into_iter()
                .filter(|r| manageable.iter().any(|m| m == r))
                .collect();
            // 同组管理员/其他员工可见但不可操作
            let is_admin = has_role(&u.role, "admin");
            let is_staff = has_role(&u.role, "staff");
            json!({
                "username": u.username,
                "full_name": u.full_name,
                "role": visible_tags.join(","),
                "is_admin": is_admin,
                "is_staff": is_staff,
            })
        })
        .collect();

    Json(json!({ "users": list })).into_response()
}

/// 员工标签管理：为其他用户添加标签。
///
/// Body：`{ "username": 目标用户, "full_name": 目标姓名, "tag": 要添加的标签 }`。
/// 服务端会按「用户名 + 姓名」双重确认目标用户，避免误加到他人。
/// 仅允许添加当前 staff 用户自带的标签（不含 `user` / `staff` / `admin`），且不能给自己添加。
pub async fn profile_tag_add_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<TagManageRequest>,
) -> Response {
    let (me, manageable) = match require_tag_manager(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let tag = payload.tag.trim().to_string();
    if !manageable.iter().any(|t| *t == tag) {
        return Json(json!({"error": "您不能管理该标签"})).into_response();
    }

    let target_username = payload.username.trim().to_string();
    if target_username.is_empty() {
        return Json(json!({"error": "用户名不能为空"})).into_response();
    }
    if target_username == me {
        return Json(json!({"error": "不能给自己添加标签"})).into_response();
    }

    // 添加标签必须提供目标姓名，服务端核对后再操作
    let full_name = payload
        .full_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if full_name.is_empty() {
        return Json(json!({"error": "请填写目标用户的姓名"})).into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let target = match db::get_user_full_info(&conn, &target_username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    // 姓名核对：与数据库中记录完全一致
    if target.full_name.trim() != full_name {
        return Json(json!({
            "error": "用户名与姓名不匹配，请核对后再试"
        }))
        .into_response();
    }

    // staff 不能对其他带 staff 标签的用户执行添加操作
    if has_role(&target.role, "staff") {
        return Json(json!({"error": "不能对 staff 用户添加标签"})).into_response();
    }

    // 管理员的标签由管理员在管理控制台维护，staff 不能操作
    if has_role(&target.role, "admin") {
        return Json(json!({"error": "不能对管理员用户添加标签"})).into_response();
    }

    if has_role(&target.role, &tag) {
        return Json(json!({
            "error": format!("用户 {} 已拥有标签 {}", target_username, tag)
        }))
        .into_response();
    }

    let new_role = add_tag_to_role(&target.role, &tag);
    if let Err(_) = db::set_user_role(&conn, &target.uid, &new_role) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({
        "success": true,
        "message": format!("已为 {}（{}）添加标签 {}", target_username, target.full_name, tag)
    }))
    .into_response()
}

/// 员工标签管理：移除其他用户的标签。
///
/// Body：`{ "username": 目标用户, "tag": 要移除的标签 }`。
/// 仅允许移除当前 staff 用户自带的标签（不含 `user` / `staff` / `admin`），且不能移除自己的标签。
/// 同组管理员（带 `admin` 标签）的用户可见但**不允许移除其标签**。
pub async fn profile_tag_remove_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<TagManageRequest>,
) -> Response {
    let (me, manageable) = match require_tag_manager(&state, &jar) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let tag = payload.tag.trim().to_string();
    if !manageable.iter().any(|t| *t == tag) {
        return Json(json!({"error": "您不能管理该标签"})).into_response();
    }

    let target_username = payload.username.trim().to_string();
    if target_username.is_empty() {
        return Json(json!({"error": "用户名不能为空"})).into_response();
    }
    // staff 不能移除自己的标签
    if target_username == me {
        return Json(json!({"error": "不能移除自己的标签"})).into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    let target = match db::get_user_full_info(&conn, &target_username) {
        Ok(Some(u)) => u,
        _ => return Json(json!({"error": "用户不存在"})).into_response(),
    };

    // staff 不能对其他带 staff 标签的用户执行移除操作
    if has_role(&target.role, "staff") {
        return Json(json!({"error": "不能对 staff 用户移除标签"})).into_response();
    }

    // 同组管理员可见但不可操作：不允许移除管理员的标签
    if has_role(&target.role, "admin") {
        return Json(json!({"error": "不能移除管理员用户的标签"})).into_response();
    }

    if !has_role(&target.role, &tag) {
        return Json(json!({
            "error": format!("用户 {} 没有标签 {}", target_username, tag)
        }))
        .into_response();
    }

    let new_role = remove_tag_from_role(&target.role, &tag);
    if let Err(_) = db::set_user_role(&conn, &target.uid, &new_role) {
        return Json(json!({"error": "内部错误"})).into_response();
    }

    Json(json!({
        "success": true,
        "message": format!("已移除 {} 的标签 {}", target_username, tag)
    }))
    .into_response()
}
