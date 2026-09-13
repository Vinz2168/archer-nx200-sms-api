//! Client e server MCP per il pannello di gestione dei router TP-Link Archer
//! con SIM 4G/5G (firmware "GDPR encrypt", testato su Archer NX200).
//!
//! Vedi PROTOCOL.md e README.md nella root del repository per il protocollo
//! e per la configurazione.

pub mod client;
pub mod crypto;
pub mod rest;
pub mod server;
