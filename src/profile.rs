//! 个人中心 API 处理器

use axum::{Json, extract::State, response::{IntoResponse, Response}};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;
use std::sync::Arc;

use crate::db;
use crate::state::AppState;
use crate::utils::parse_roles;

pub async fn profile_api_handler(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let session_id = match jar.get("sso_session") {
        Some(c) => c.value().to_string(),
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "未登录"})),
            )
                .into_response();
        }
    };

    // 从session_store查询用户信息及是否管理员会话
    let (username, session_is_admin) = match state.session_store.lock().unwrap().get(&session_id) {
        Some(session) => (session.username.clone(), session.is_admin),
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "会话无效或已过期"})),
            )
                .into_response();
        }
    };

    // 管理员会话：返回管理员用户中心的专属信息
    if session_is_admin {
        return Json(json!({
            "username": username,
            "role": "admin",
            "external_uid": "",
            "full_name": "管理员",
            "student_id": "",
            "gender": "",
            "last_login_time": null,
            "state": 0,
            "state_description": null,
            "restriction_end_time": null,
            "flag": 1,
            "login_attempts": [],
            "is_admin": true,
        }))
        .into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return Json(json!({"error": "内部错误"})).into_response(),
    };

    match db::get_user_full_info(&conn, &username) {
        Ok(Some(user_info)) => {
            let login_attempts = db::get_recent_login_attempts(
                &conn,
                &user_info.uid,
                state.config.login_record_window,
            )
            .unwrap_or_default();

            // 标签管理权限：仅非管理员会话中的 staff 用户可管理其自带的标签
            // （排除基线角色 `user` 与提权风险角色 `staff` / `admin`）
            let roles = parse_roles(&user_info.role);
            let is_staff = roles.iter().any(|r| r == "staff");
            let manageable_tags: Vec<String> = roles
                .iter()
                .filter(|r| r.as_str() != "staff" && r.as_str() != "admin" && r.as_str() != "user")
                .cloned()
                .collect();

            Json(json!({
                "username": user_info.username,
                "role": user_info.role,
                "external_uid": user_info.external_uid,
                "student_id": user_info.student_id,
                "full_name": user_info.full_name,
                "gender": user_info.gender,
                "last_login_time": user_info.last_login_time,
                "state": user_info.state,
                "state_description": user_info.state_description,
                "restriction_end_time": user_info.restriction_end_time,
                "flag": user_info.flag,
                "login_attempts": login_attempts,
                "can_manage_tags": is_staff,
                "manageable_tags": manageable_tags,
            }))
            .into_response()
        }
        // 用户不存在或查询失败时返回默认信息
        _ => Json(json!({
            "username": username,
            "role": "user",
            "external_uid": "",
            "full_name": "",
            "state": 0,
            "state_description": null,
            "flag": 0,
            "login_attempts": [],
        }))
        .into_response(),
    }
}
