//! Invia UN SMS reale tramite il router — NON eseguito da `cargo test` e
//! separato da `live_check` (sola lettura) deliberatamente: questo esempio
//! ha un effetto reale (spedisce un messaggio), va lanciato solo di
//! proposito, con destinatario e testo espliciti.
//!
//! Uso:
//!   ARCHER_SMS_TO='+39...' ARCHER_SMS_TEXT='...' ARCHER_PASSWORD='...' \
//!     cargo run --release --example send_test_sms
//!
//! Altre variabili d'ambiente: stesse di `main.rs` (ARCHER_ROUTER_URL,
//! ARCHER_USERNAME, ARCHER_TRUST_ALL_CERTS).

use mcp_archer_router::client::{ArcherConfig, ArcherSession};

#[tokio::main]
async fn main() {
    let to = std::env::var("ARCHER_SMS_TO")
        .expect("imposta ARCHER_SMS_TO (numero destinatario, es. +393331234567)");
    let text =
        std::env::var("ARCHER_SMS_TEXT").expect("imposta ARCHER_SMS_TEXT (testo del messaggio)");

    let config = ArcherConfig {
        url: std::env::var("ARCHER_ROUTER_URL").unwrap_or_else(|_| "https://192.168.10.1".to_string()),
        username: std::env::var("ARCHER_USERNAME").unwrap_or_else(|_| "user".to_string()),
        password: std::env::var("ARCHER_PASSWORD")
            .expect("imposta ARCHER_PASSWORD (password del pannello del router) prima di lanciare questo esempio"),
        trust_all_certs: std::env::var("ARCHER_TRUST_ALL_CERTS").map(|v| v != "false" && v != "0").unwrap_or(true),
    };

    println!("--- invio SMS a {to} tramite {} ---", config.url);
    let session = ArcherSession::new(config);
    match session.send_sms(&to, &text, true).await {
        Ok(result) => {
            println!("OK: {}", serde_json::to_string_pretty(&result).unwrap());
        }
        Err(e) => {
            println!("FALLITO: {e}");
            std::process::exit(1);
        }
    }
}
