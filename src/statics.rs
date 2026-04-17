#[cfg(debug_assertions)]
use axum::http::StatusCode;

use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use axum::extract::State;
use std::sync::Arc;
use crate::AppState;

pub async fn login_page_handler(State(state): State<Arc<AppState>>, jar: CookieJar) -> Response {
    // 检查是否有cookie，如果有，显示继续页面
    let session_id = jar.get("sso_session").map(|c| c.value().to_string());
    let username = if let Some(ref sid) = session_id {
        state.session_store.lock().unwrap()
            .get(sid)
            .map(|s| s.username.clone())
    } else {
        None
    };

    // 2. 开发环境下：动态读取文件，支持热更新
    #[cfg(debug_assertions)]
    {
        if let Some(user) = username {
            return match tokio::fs::read_to_string("static/continue.html").await {
                Ok(html) => Html(html.replace("{{username}}", &user)).into_response(),
                Err(_) => (StatusCode::NOT_FOUND, "continue.html missing").into_response(),
            };
        }

        match tokio::fs::read_to_string("static/login.html").await {
            Ok(html) => Html(html).into_response(),
            Err(_) => (StatusCode::NOT_FOUND, "login.html missing").into_response(),
        }
    }

    // 3. 发布/Debug之外环境下：编译时嵌入，追求极致性能
    #[cfg(not(debug_assertions))]
    {
        static CONTINUE_HTML: &str = include_str!("../static/continue.html");
        static LOGIN_HTML: &str = include_str!("../static/login.html");

        if let Some(user) = username {
            return Html(CONTINUE_HTML.replace("{{username}}", &user)).into_response();
        }

        Html(LOGIN_HTML).into_response()
    }
}

pub async fn profile_page_handler(jar: CookieJar) -> Response {
    // 检查cookie是否存在，实际验证由客户端在/auth/profile/api中程成
    if jar.get("sso_session").is_none() {
        return Redirect::to("/auth/").into_response();
    }

    #[cfg(debug_assertions)]
    {
        // 开发模式：实时读取文件，方便调试
        match tokio::fs::read_to_string("static/profile.html").await {
            Ok(html) => Html(html).into_response(),
            Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
        }
    }

    #[cfg(not(debug_assertions))]
    {
        // 发布模式：编译时嵌入，追求极致性能
        static HTML: &str = include_str!("../static/profile.html");
        Html(HTML).into_response()
    }
}

pub async fn agreement_html_handler() -> Response {
    #[cfg(debug_assertions)]
    {
        tokio::fs::read_to_string("static/agreement.html")
            .await
            .map(Html)
            .map_err(|_| (StatusCode::NOT_FOUND, "agreement.html not found"))
            .into_response()
    }

    #[cfg(not(debug_assertions))]
    {
        static HTML: &str = include_str!("../static/agreement.html");
        Html(HTML).into_response()
    }
}

pub async fn agreement_md_handler() -> Response {
    #[cfg(debug_assertions)]
    {
        tokio::fs::read_to_string("static/AGREEMENT.md")
            .await
            .map(|content| {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/markdown")],
                    content,
                )
            })
            .map_err(|_| (StatusCode::NOT_FOUND, "AGREEMENT.md not found"))
            .into_response()
    }

    #[cfg(not(debug_assertions))]
    {
        static MD: &str = include_str!("../static/AGREEMENT.md");
        ([(axum::http::header::CONTENT_TYPE, "text/markdown")], MD).into_response()
    }
}
