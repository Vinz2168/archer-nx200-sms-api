//! Test manuale contro un router reale — NON eseguito da `cargo test`.
//!
//! Prova login + `sim_info` + `sms_inbox` (sola lettura, nessun SMS viene
//! inviato) usando le stesse `ArcherConfig`/`ArcherSession` del server MCP,
//! e stampa solo esiti/dati di diagnostica: la password letta dall'ambiente
//! non viene mai stampata.
//!
//! Uso:
//!   ARCHER_PASSWORD='...' cargo run --release --example live_check
//!
//! Variabili d'ambiente: stesse di `main.rs` (ARCHER_ROUTER_URL,
//! ARCHER_USERNAME, ARCHER_PASSWORD, ARCHER_TRUST_ALL_CERTS).

use mcp_archer_router::client::{ArcherConfig, ArcherSession};

#[tokio::main]
async fn main() {
    let config = ArcherConfig {
        url: std::env::var("ARCHER_ROUTER_URL").unwrap_or_else(|_| "https://192.168.10.1".to_string()),
        username: std::env::var("ARCHER_USERNAME").unwrap_or_else(|_| "user".to_string()),
        password: std::env::var("ARCHER_PASSWORD")
            .expect("imposta ARCHER_PASSWORD (password del pannello del router) prima di lanciare questo esempio"),
        trust_all_certs: std::env::var("ARCHER_TRUST_ALL_CERTS").map(|v| v != "false" && v != "0").unwrap_or(true),
    };
    println!(
        "--- mcp-archer-router: test dal vivo contro {} (utente {:?}) ---",
        config.url, config.username
    );

    let session = ArcherSession::new(config);
    let mut failures = 0;

    print!("[1/2] sim_info ... ");
    match session.sim_info().await {
        Ok(info) => println!("OK: {}", serde_json::to_string_pretty(&info).unwrap()),
        Err(e) => {
            println!("FALLITO: {e}");
            failures += 1;
        }
    }

    print!("[2/2] sms_inbox (pagina 0) ... ");
    match session.inbox(0).await {
        Ok(page) => println!(
            "OK: {} messaggi in questa pagina, {} totali, {} non letti",
            page.entries.len(),
            page.total_number
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
            page.unread_number
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into())
        ),
        Err(e) => {
            println!("FALLITO: {e}");
            failures += 1;
        }
    }

    println!("---");
    if failures == 0 {
        println!("Tutto OK.");
    } else {
        println!("{failures} operazione/i fallita/e.");
        std::process::exit(1);
    }
}
