//! Agents in the API (§21.7 G12): `GET /api/v1/agents` for everyone who
//! may read, and for logged-in admins an enrollment token
//! (`POST /api/v1/agents/enroll-token`) and revocation
//! (`DELETE /api/v1/agents/{name}`).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;

use crate::auth::Caller;
use crate::users::Role;
use crate::{AppState, error};

/// What the rest of the server does for these endpoints. Errors carry the
/// status to answer with and a message for people.
pub trait AgentAdmin: Send + Sync {
    /// `{"agents": [...], "tokens": [...]}`: enrolled agents with their
    /// state now, and enrollment tokens not used yet.
    fn list(&self) -> serde_json::Value;
    /// A single-use enrollment token for `name`: the token text and when
    /// it expires (Unix ms).
    fn add_token(&self, name: &str) -> Result<(String, i64), (StatusCode, String)>;
    /// Refuse the agent's certificate from now on.
    fn revoke(&self, name: &str) -> Result<(), (StatusCode, String)>;
}

pub(crate) async fn list(State(s): State<Arc<AppState>>) -> Response {
    let Some(a) = s.agents.clone() else {
        return Json(serde_json::json!({ "enabled": false, "agents": [], "tokens": [] }))
            .into_response();
    };
    match tokio::task::spawn_blocking(move || a.list()).await {
        Ok(mut v) => {
            // Whether this server takes agents at all, so the UI can
            // offer the Agents page before the first one is enrolled.
            v["enabled"] = true.into();
            Json(v).into_response()
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Why the caller may not enroll or revoke agents, if so: only an admin
/// who logged in may.
#[allow(clippy::result_large_err)] // the error is the response itself
fn admin(s: &AppState, c: &Caller) -> Result<Arc<dyn AgentAdmin>, Response> {
    if c.name.is_none() || c.role < Role::Admin {
        return Err(error(
            StatusCode::FORBIDDEN,
            "only a logged-in admin can enroll or revoke agents; \
             on the server use `routelith ctl agent`",
        ));
    }
    s.agents.clone().ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            "this server takes no agents (set listen_agents)",
        )
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenBody {
    name: String,
}

pub(crate) async fn enroll_token(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    body: Result<Json<TokenBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let a = match admin(&s, &caller) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Ok(Json(b)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "send JSON: {\"name\": \"<agent>\"}",
        );
    };
    let name = b.name.clone();
    match tokio::task::spawn_blocking(move || a.add_token(&name)).await {
        Ok(Ok((token, expires_ms))) => Json(serde_json::json!({
            "name": b.name,
            "token": token,
            "expires_ms": expires_ms,
        }))
        .into_response(),
        Ok(Err((status, msg))) => error(status, msg),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(crate) async fn revoke(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
) -> Response {
    let a = match admin(&s, &caller) {
        Ok(a) => a,
        Err(r) => return r,
    };
    match tokio::task::spawn_blocking(move || a.revoke(&name)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err((status, msg))) => error(status, msg),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
