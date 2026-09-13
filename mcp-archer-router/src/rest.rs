//! Espone [`crate::client::ArcherSession`] anche come API REST semplice
//! (JSON su HTTP), in alternativa o in aggiunta al server MCP - vedi
//! `main.rs` per come le due cose vengono accese/spente indipendentemente.
//!
//! Nessuna autenticazione: pensata per essere esposta solo su localhost o su
//! una rete già fidata (vedi `ARCHER_REST_BIND` in README.md). Ogni errore
//! verso il router viene loggato (livello ERROR, via `tracing`) prima di
//! essere tradotto in una risposta JSON `{"error": "..."}`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::client::{ArcherError, ArcherSession, InboxPage, SendSmsResult, SimInfo};

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

type ApiError = (StatusCode, Json<ErrorBody>);

/// Logga l'errore (vedi [`ArcherError::logged`]) e lo traduce in una
/// risposta HTTP. Sempre 502 Bad Gateway: l'errore è sempre "il router non
/// ha risposto correttamente", mai una richiesta malformata lato client
/// (quelle sono già filtrate dal deserializer di axum, che risponde 400/422
/// per conto suo prima ancora di arrivare qui).
fn to_api_error(operation: &str, e: ArcherError) -> ApiError {
    let e = e.logged("rest", operation);
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorBody {
            error: e.to_string(),
        }),
    )
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct InboxQuery {
    #[serde(default)]
    page: u32,
}

async fn get_inbox(
    State(session): State<Arc<ArcherSession>>,
    Query(q): Query<InboxQuery>,
) -> Result<Json<InboxPage>, ApiError> {
    session
        .inbox(q.page)
        .await
        .map(Json)
        .map_err(|e| to_api_error("sms_inbox", e))
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct SendSmsBody {
    to: String,
    text: String,
    #[serde(default = "default_true")]
    wait_result: bool,
}

async fn post_send_sms(
    State(session): State<Arc<ArcherSession>>,
    Json(body): Json<SendSmsBody>,
) -> Result<Json<SendSmsResult>, ApiError> {
    session
        .send_sms(&body.to, &body.text, body.wait_result)
        .await
        .map(Json)
        .map_err(|e| to_api_error("sms_send", e))
}

async fn get_sim_info(
    State(session): State<Arc<ArcherSession>>,
) -> Result<Json<SimInfo>, ApiError> {
    session
        .sim_info()
        .await
        .map(Json)
        .map_err(|e| to_api_error("sim_info", e))
}

/// Costruisce il router axum. `session` è condivisa con il server MCP
/// quando entrambi i transport sono attivi (vedi `main.rs`): un solo login
/// in cache, non uno per transport.
pub fn router(session: Arc<ArcherSession>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/sms/inbox", get(get_inbox))
        .route("/sms/send", post(post_send_sms))
        .route("/sim/info", get(get_sim_info))
        .with_state(session)
}
