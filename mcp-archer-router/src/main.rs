//! Server MCP e/o REST per il pannello di gestione dei router TP-Link Archer
//! con SIM 4G/5G (firmware "GDPR encrypt", testato su Archer NX200).
//!
//! Vedi PROTOCOL.md e README.md nella root del repository per il protocollo
//! e per la configurazione. Riproduce le stesse funzionalità del client
//! Python (`archer_sms.py`) e del processor NiFi (`nifi-archer-router/`):
//! lettura della posta in arrivo SMS, invio SMS, info SIM/rete/consumo dati.
//!
//! Configurazione via variabili d'ambiente:
//! - `ARCHER_ROUTER_URL` (default `https://192.168.10.1`)
//! - `ARCHER_USERNAME` (default `user`)
//! - `ARCHER_PASSWORD` (obbligatoria)
//! - `ARCHER_TRUST_ALL_CERTS` (default `true`: il pannello usa un
//!   certificato TLS autofirmato senza subject/SAN, vedi PROTOCOL.md §6.3)
//! - `ARCHER_MCP_ENABLED` (default `true`): server MCP su stdio.
//! - `ARCHER_REST_ENABLED` (default `false`): API REST JSON su HTTP.
//! - `ARCHER_REST_BIND` (default `127.0.0.1:8787`, solo se REST è attivo).
//!
//! Almeno uno tra MCP e REST deve restare attivo; entrambi possono esserlo
//! insieme, condividendo la stessa sessione (login) verso il router.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use mcp_archer_router::client::{ArcherConfig, ArcherSession};
use mcp_archer_router::server::ArcherRouterServer;

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => v != "false" && v != "0",
        Err(_) => default,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Tutto il logging va su stderr: stdout è il canale del protocollo MCP
    // quando quel transport è attivo, e non va sporcato in nessun caso.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let config = ArcherConfig {
        url: std::env::var("ARCHER_ROUTER_URL")
            .unwrap_or_else(|_| "https://192.168.10.1".to_string()),
        username: std::env::var("ARCHER_USERNAME").unwrap_or_else(|_| "user".to_string()),
        password: std::env::var("ARCHER_PASSWORD").context(
            "variabile d'ambiente ARCHER_PASSWORD non impostata (password del pannello del router)",
        )?,
        trust_all_certs: env_flag("ARCHER_TRUST_ALL_CERTS", true),
    };
    let mcp_enabled = env_flag("ARCHER_MCP_ENABLED", true);
    let rest_enabled = env_flag("ARCHER_REST_ENABLED", false);
    let rest_bind =
        std::env::var("ARCHER_REST_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    if !mcp_enabled && !rest_enabled {
        bail!(
            "sia ARCHER_MCP_ENABLED che ARCHER_REST_ENABLED sono a false: nessun transport da avviare \
             (impostane almeno uno a true, o lascia il default: MCP attivo)"
        );
    }

    tracing::info!(
        url = %config.url,
        username = %config.username,
        mcp_enabled,
        rest_enabled,
        "Avvio mcp-archer-router"
    );

    // Sessione condivisa: se entrambi i transport sono attivi devono usare
    // la stessa cache di login, non autenticarsi ciascuno per conto proprio
    // (il router accetta una sola sessione amministrativa alla volta - vedi
    // PROTOCOL.md §6.1: due login indipendenti si scavalcherebbero a
    // vicenda in continuazione).
    let session = Arc::new(ArcherSession::new(config));

    match (mcp_enabled, rest_enabled) {
        (true, true) => {
            tokio::select! {
                res = run_mcp(Arc::clone(&session)) => res,
                res = run_rest(session, rest_bind) => res,
            }
        }
        (true, false) => run_mcp(session).await,
        (false, true) => run_rest(session, rest_bind).await,
        (false, false) => unreachable!("già verificato sopra"),
    }
}

async fn run_mcp(session: Arc<ArcherSession>) -> Result<()> {
    tracing::info!("Server MCP in ascolto su stdio");
    let server = ArcherRouterServer::new(session);
    let service = server.serve(stdio()).await.inspect_err(
        |e| tracing::error!(transport = "mcp", error = %e, "errore nell'avvio del server MCP"),
    )?;
    service
        .waiting()
        .await
        .inspect_err(|e| tracing::error!(transport = "mcp", error = %e, "il server MCP è terminato con un errore"))?;
    Ok(())
}

async fn run_rest(session: Arc<ArcherSession>, bind: String) -> Result<()> {
    let app = mcp_archer_router::rest::router(session);
    let listener = tokio::net::TcpListener::bind(&bind).await.inspect_err(|e| {
        tracing::error!(transport = "rest", addr = %bind, error = %e, "impossibile aprire il socket REST")
    })?;
    tracing::info!(transport = "rest", addr = %bind, "Server REST in ascolto (nessuna autenticazione: esporre solo su reti fidate)");
    axum::serve(listener, app)
        .await
        .inspect_err(|e| tracing::error!(transport = "rest", error = %e, "il server REST è terminato con un errore"))?;
    Ok(())
}
