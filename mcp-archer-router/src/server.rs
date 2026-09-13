//! Espone [`crate::client::ArcherSession`] come server MCP (tool
//! `sms_inbox`, `sms_send`, `sim_info`) su transport stdio.

use std::sync::Arc;

use rmcp::{
    Json, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, InitializeResult, ServerCapabilities},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::client::{ArcherSession, InboxPage, SendSmsResult, SimInfo};

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InboxParams {
    /// Numero di pagina (0-based) della posta in arrivo da leggere.
    #[serde(default)]
    pub page: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendSmsParams {
    /// Numero di telefono del destinatario, es. +393331234567.
    pub to: String,
    /// Testo del messaggio da inviare.
    pub text: String,
    /// Se true (default), attende fino a 20s l'esito dell'invio invece di
    /// ritornare solo l'accodamento.
    #[serde(default = "default_true")]
    pub wait_result: bool,
}

#[derive(Clone)]
pub struct ArcherRouterServer {
    session: Arc<ArcherSession>,
    tool_router: ToolRouter<Self>,
}

impl ArcherRouterServer {
    /// La sessione è passata già condivisa (`Arc`) perché può essere la
    /// stessa usata in parallelo dal server REST (vedi `main.rs`): il
    /// router accetta una sola sessione amministrativa alla volta, quindi
    /// MCP e REST devono condividere esattamente la stessa cache di login,
    /// non autenticarsi ciascuno per conto proprio.
    pub fn new(session: Arc<ArcherSession>) -> Self {
        Self {
            session,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router(router = tool_router)]
impl ArcherRouterServer {
    #[tool(
        description = "Elenca gli SMS nella posta in arrivo del router (pannello TP-Link Archer con SIM 4G/5G)."
    )]
    async fn sms_inbox(
        &self,
        Parameters(InboxParams { page }): Parameters<InboxParams>,
    ) -> Result<Json<InboxPage>, String> {
        self.session
            .inbox(page)
            .await
            .map(Json)
            .map_err(|e| e.logged("mcp", "sms_inbox").to_string())
    }

    #[tool(description = "Invia un SMS tramite il router.")]
    async fn sms_send(
        &self,
        Parameters(SendSmsParams {
            to,
            text,
            wait_result,
        }): Parameters<SendSmsParams>,
    ) -> Result<Json<SendSmsResult>, String> {
        self.session
            .send_sms(&to, &text, wait_result)
            .await
            .map(Json)
            .map_err(|e| e.logged("mcp", "sms_send").to_string())
    }

    #[tool(
        description = "Info SIM/rete/consumo dati del router: ICCID/IMSI, segnale, IP assegnato, traffico dati totale e odierno."
    )]
    async fn sim_info(&self) -> Result<Json<SimInfo>, String> {
        self.session
            .sim_info()
            .await
            .map(Json)
            .map_err(|e| e.logged("mcp", "sim_info").to_string())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ArcherRouterServer {
    fn get_info(&self) -> InitializeResult {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Client non ufficiale per il pannello di gestione dei router TP-Link Archer con SIM 4G/5G \
                 (firmware \"GDPR encrypt\", es. Archer NX200): sms_inbox (posta in arrivo), sms_send (invio SMS), \
                 sim_info (ICCID/IMSI, segnale, IP, consumo dati). Login lazy con retry automatico se la sessione \
                 viene rubata da un altro login (es. la GUI del browser: il router accetta una sola sessione alla \
                 volta)."
                    .to_string(),
            )
    }
}
