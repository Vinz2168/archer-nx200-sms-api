//! Client per il pannello TP-Link Archer ("GDPR encrypt") e gestione dello
//! stato di sessione con login lazy e retry automatico.
//!
//! Due livelli:
//! - [`ArcherClient`]: protocollo a basso/medio livello, non tiene conto di
//!   sessioni scadute - una chiamata dati che fallisce con un HTTP non-200
//!   ritorna [`ArcherError::SessionExpired`].
//! - [`ArcherSession`]: quello usato dal server MCP. Fa login lazy alla
//!   prima chiamata, tiene la sessione in cache tra una tool-call e l'altra
//!   e, se una chiamata fallisce con `SessionExpired` (tipicamente perché
//!   qualcun altro si è loggato nel frattempo, es. dalla GUI del browser -
//!   vedi PROTOCOL.md §6.1), si ri-autentica e ritenta una volta sola.

use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::crypto;

const DEFAULT_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const CONNECT_ATTEMPTS: u32 = 4;
/// Backoff fra un retry e l'altro su un HTTP 406/500 transitorio (vedi
/// `send_raw`). Breve e fisso, non crescente: non è un vero errore di rete,
/// è un hiccup del webserver embedded che si risolve in fretta o non si
/// risolve affatto.
const TRANSIENT_STATUS_RETRY_DELAY: Duration = Duration::from_millis(150);

#[derive(Debug, thiserror::Error)]
pub enum ArcherError {
    #[error("errore di rete verso il router: {0}")]
    Network(#[from] reqwest::Error),
    /// Una chiamata dati post-login ha ricevuto un HTTP non-200: segnale che
    /// la sessione corrente non è più valida (vedi PROTOCOL.md §3.1/§6.1).
    #[error("sessione scaduta o non valida (HTTP {0})")]
    SessionExpired(u16),
    #[error("login fallito: {0}")]
    LoginFailed(String),
    #[error("errore di protocollo: {0}")]
    Protocol(String),
}

impl ArcherError {
    /// Logga l'errore (livello ERROR, via `tracing`, quindi su stderr) con
    /// il contesto di chi l'ha originato, poi lo ritorna invariato. Usato da
    /// entrambi i transport (MCP e REST, vedi `server.rs`/`rest.rs`) per non
    /// perdere gli errori verso il router nel solo messaggio ritornato al
    /// chiamante: finiscono anche nei log del processo.
    pub fn logged(self, transport: &str, operation: &str) -> Self {
        tracing::error!(transport, operation, error = %self, "chiamata al router fallita");
        self
    }
}

/// Configurazione statica per raggiungere un router: URL, credenziali,
/// se fidarsi del certificato TLS autofirmato (necessario su questi router,
/// vedi PROTOCOL.md §6.3).
pub struct ArcherConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub trust_all_certs: bool,
}

// --------------------------------------------------------------------- //
// Tipi di risultato esposti come output strutturato dei tool MCP
// --------------------------------------------------------------------- //

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct InboxEntry {
    pub index: Option<String>,
    pub from: Option<String>,
    pub content: Option<String>,
    pub received_time: Option<String>,
    pub unread: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct InboxPage {
    pub entries: Vec<InboxEntry>,
    pub total_number: Option<i64>,
    pub unread_number: Option<i64>,
    pub page_number: Option<i64>,
    pub amount_per_page: Option<i64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SendSmsResult {
    pub success: bool,
    /// Codice di esito riportato dal router ("1" = inviato con successo;
    /// altri valori non mappati = probabile errore). `None` se non atteso
    /// (`wait_result: false`) o se non è stato possibile confermarlo.
    pub send_result: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SimInfo {
    pub iccid: Option<String>,
    pub imsi: Option<String>,
    pub msisdn: Option<String>,
    pub sim_status: Option<String>,
    pub signal_strength: Option<String>,
    pub sms_center: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub dns: Vec<Option<String>>,
    pub connected_bands: Option<String>,
    pub roaming: bool,
    pub total_used_gb: f64,
    pub today_used_mb: f64,
    pub data_limit_enabled: bool,
    pub data_limit_bytes: Option<String>,
}

// --------------------------------------------------------------------- //
// Client a basso/medio livello
// --------------------------------------------------------------------- //

pub struct ArcherClient {
    http: reqwest::Client,
    base_url: String,
    username: String,
    nn: String,
    ee: String,
    seq: u64,
    hash: String,
    aes_key: String,
    aes_iv: String,
    jsessionid: Option<String>,
    token: String,
}

impl ArcherClient {
    pub fn new(base_url: &str, username: &str, trust_all_certs: bool) -> Result<Self, ArcherError> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(trust_all_certs)
            // Il webserver embedded del router non gestisce correttamente il
            // keep-alive quando il corpo della richiesta contiene CRLF
            // letterali (il formato "sign=...\r\ndata=...\r\n" usato da
            // /cgi_gdpr): riusare la stessa connessione TCP per la richiesta
            // successiva produce spesso "406" o la chiusura brusca della
            // connessione (vedi PROTOCOL.md §6.2). Disabilitando il pool di
            // connessioni idle si forza una connessione nuova ad ogni
            // richiesta, come fanno i client Python/Java di riferimento.
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            username: username.to_string(),
            nn: String::new(),
            ee: String::new(),
            seq: 0,
            hash: String::new(),
            aes_key: String::new(),
            aes_iv: String::new(),
            jsessionid: None,
            token: "0".to_string(),
        })
    }

    // -- basso livello ---------------------------------------------------- //

    async fn send_raw(
        &mut self,
        path: &str,
        method: reqwest::Method,
        body: Vec<u8>,
        extra_header: Option<(&str, &str)>,
    ) -> Result<reqwest::Response, ArcherError> {
        let url = format!("{}{}", self.base_url, path);
        let mut last_err = None;
        for attempt in 0..CONNECT_ATTEMPTS {
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header("User-Agent", DEFAULT_UA)
                .header("Referer", format!("{}/", self.base_url))
                .header("Connection", "close")
                .header("TokenID", &self.token);
            if let Some(jsid) = &self.jsessionid {
                req = req.header("Cookie", format!("JSESSIONID={jsid}"));
            }
            if let Some((k, v)) = extra_header {
                req = req.header(k, v);
            }
            req = req.body(body.clone());

            match req.send().await {
                Ok(resp) => {
                    if let Some(jsid) = extract_jsessionid(&resp) {
                        self.jsessionid = Some(jsid);
                    }
                    let status = resp.status();
                    let last_attempt = attempt + 1 == CONNECT_ATTEMPTS;
                    // Il webserver embedded del router risponde a volte con 406
                    // o 500 come puro hiccup transitorio, non un rifiuto reale -
                    // confermato indipendentemente dal client Python
                    // tplinkrouterc6u (tplinkrouterc6u/client/mr.py: stesso
                    // pattern, retry su 406/500 con breve backoff, su ogni
                    // richiesta). Va distinto da un 406 "vero" su una chiamata
                    // dati post-login, che invece segnala sessione scaduta
                    // (vedi ArcherError::SessionExpired in signed_post): qui ci
                    // limitiamo a filtrare il rumore a livello di trasporto,
                    // prima che quella logica entri in gioco.
                    if !last_attempt && matches!(status.as_u16(), 406 | 500) {
                        tokio::time::sleep(TRANSIENT_STATUS_RETRY_DELAY).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(300 * (attempt as u64 + 1))).await;
                }
            }
        }
        // Se si arriva qui, ogni tentativo è fallito a livello di rete: un
        // esito Ok, anche con status 406/500 sull'ultimo tentativo, ritorna
        // sempre prima con `return Ok(resp)` sopra.
        Err(ArcherError::Network(
            last_err.expect("almeno un tentativo eseguito"),
        ))
    }

    async fn fetch_gdpr_parm(&mut self) -> Result<(), ArcherError> {
        let resp = self
            .send_raw("/cgi/getGDPRParm", reqwest::Method::POST, Vec::new(), None)
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(ArcherError::Protocol(format!(
                "getGDPRParm ha risposto HTTP {status}"
            )));
        }
        let mut nn = None;
        let mut ee = None;
        let mut seq = None;
        for line in body.lines() {
            let line = line.trim().trim_end_matches(';');
            let Some(rest) = line.strip_prefix("var ") else {
                continue;
            };
            let Some((k, v)) = rest.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "nn" => nn = Some(v),
                "ee" => ee = Some(v),
                "seq" => seq = v.parse::<u64>().ok(),
                _ => {}
            }
        }
        self.nn =
            nn.ok_or_else(|| ArcherError::Protocol("getGDPRParm: campo nn mancante".into()))?;
        self.ee =
            ee.ok_or_else(|| ArcherError::Protocol("getGDPRParm: campo ee mancante".into()))?;
        self.seq = seq.ok_or_else(|| {
            ArcherError::Protocol("getGDPRParm: campo seq mancante/non numerico".into())
        })?;
        Ok(())
    }

    async fn signed_post(
        &mut self,
        plaintext_json: &str,
        is_login: bool,
    ) -> Result<String, ArcherError> {
        let cipher_b64 = crypto::aes_encrypt(plaintext_json, &self.aes_key, &self.aes_iv);
        let s_val = self.seq + cipher_b64.len() as u64;
        let sign_input = if is_login {
            format!(
                "key={}&iv={}&h={}&s={}",
                self.aes_key, self.aes_iv, self.hash, s_val
            )
        } else {
            format!("h={}&s={}", self.hash, s_val)
        };
        let sign = crypto::rsa_raw_encrypt(&sign_input, &self.nn, &self.ee)
            .map_err(ArcherError::Protocol)?;
        let body = format!("sign={sign}\r\ndata={cipher_b64}\r\n");

        let resp = self
            .send_raw(
                "/cgi_gdpr?9",
                reqwest::Method::POST,
                body.into_bytes(),
                Some(("Content-Type", "text/plain")),
            )
            .await?;
        let status = resp.status();
        let body_text = resp.text().await?;
        if !status.is_success() {
            let msg = format!(
                "/cgi_gdpr ha risposto HTTP {status} (token/cookie di sessione mancante o scaduto?)"
            );
            return if is_login {
                Err(ArcherError::Protocol(msg))
            } else {
                Err(ArcherError::SessionExpired(status.as_u16()))
            };
        }
        Ok(crypto::aes_decrypt(&body_text, &self.aes_key, &self.aes_iv))
    }

    /// Chiamata dati generica post-login. `operation` tipicamente "go"
    /// (get), "so" (set), "gl" (get list).
    async fn call(
        &mut self,
        oid: &str,
        operation: &str,
        data: Value,
    ) -> Result<Value, ArcherError> {
        let payload = json!({"data": data, "operation": operation, "oid": oid});
        let raw = self.signed_post(&payload.to_string(), false).await?;
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(raw)
            .map_err(|e| ArcherError::Protocol(format!("risposta non-JSON da {oid}: {e}")))
    }

    // -- alto livello ------------------------------------------------------ //

    pub async fn login(&mut self, password: &str) -> Result<(), ArcherError> {
        self.fetch_gdpr_parm().await?;
        self.hash = crypto::md5_hex(&format!("{}{}", self.username, password));
        let (key, iv) = crypto::random_token16_pair();
        self.aes_key = key;
        self.aes_iv = iv;

        let payload = json!({
            "data": {
                "UserName": B64.encode(&self.username),
                "Passwd": B64.encode(password),
                "Action": "1",
                "stack": "0,0,0,0,0,0",
                "pstack": "0,0,0,0,0,0",
            },
            "operation": "cgi",
            "oid": "/cgi/login",
        });
        let raw = self.signed_post(&payload.to_string(), true).await?;
        let raw = raw.trim().trim_end_matches(['\0', ';']);
        if !raw.contains("ret=0") {
            return Err(ArcherError::LoginFailed(raw.to_string()));
        }

        self.fetch_session_token().await
    }

    /// Il router non usa un vero header/cookie per il CSRF-token: dopo il
    /// login, la home page ("/"), se richiesta col cookie JSESSIONID
    /// valido, contiene `<script>var token="...";</script>` generato lato
    /// server - va estratto da qui (vedi PROTOCOL.md §2.3).
    async fn fetch_session_token(&mut self) -> Result<(), ArcherError> {
        let resp = self
            .send_raw("/", reqwest::Method::GET, Vec::new(), None)
            .await?;
        let body = resp.text().await?;
        const NEEDLE: &str = "var token=\"";
        let start = body.find(NEEDLE).ok_or_else(|| {
            ArcherError::Protocol("token di sessione non trovato nella home page".into())
        })? + NEEDLE.len();
        let end = body[start..]
            .find('"')
            .ok_or_else(|| ArcherError::Protocol("token di sessione malformato".into()))?;
        self.token = body[start..start + end].to_string();
        Ok(())
    }

    pub async fn inbox(&mut self, page: u32) -> Result<InboxPage, ArcherError> {
        self.call(
            "DEV2_LTE_SMS_RECVMSGBOX",
            "so",
            json!({"PageNumber": page.to_string(), "stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}),
        )
        .await?;
        let summary_resp = self
            .call(
                "DEV2_LTE_SMS_RECVMSGBOX",
                "go",
                json!({"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}),
            )
            .await?;
        let entries_resp = self
            .call(
                "DEV2_LTE_SMS_RECVMSGENTRY",
                "gl",
                json!({"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}),
            )
            .await?;

        let summary = summary_resp.get("data").cloned().unwrap_or(Value::Null);
        let entries = entries_resp
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|e| InboxEntry {
                index: str_field(&e, "index"),
                from: str_field(&e, "from"),
                content: str_field(&e, "content"),
                received_time: str_field(&e, "receivedTime"),
                unread: str_field(&e, "unread"),
            })
            .collect();

        Ok(InboxPage {
            entries,
            total_number: int_field(&summary, "totalNumber"),
            unread_number: int_field(&summary, "unreadNumber"),
            page_number: int_field(&summary, "pageNumber"),
            amount_per_page: int_field(&summary, "amountPerPage"),
        })
    }

    /// Invia un SMS e, se richiesto, attende l'esito facendo polling dello
    /// stato fino a un `sendResult` definitivo (max 20s). Se la sessione
    /// scade durante il polling (cioè **dopo** che l'SMS è già stato
    /// accodato con successo lato router), l'errore viene intercettato qui
    /// e trasformato in un esito "inviato ma non confermato" invece di
    /// propagare `SessionExpired`: a livello di [`ArcherSession`] questo
    /// evita che l'operazione venga ritentata da capo, il che rispedirebbe
    /// l'SMS una seconda volta.
    pub async fn send_sms(
        &mut self,
        to: &str,
        text: &str,
        wait_result: bool,
    ) -> Result<SendSmsResult, ArcherError> {
        let resp = self
            .call(
                "DEV2_LTE_SMS_SENDNEWMSG",
                "so",
                json!({"index": "1", "to": to, "textContent": text, "stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}),
            )
            .await?;
        let ok = resp
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !ok {
            return Err(ArcherError::Protocol(format!("invio SMS fallito: {resp}")));
        }
        if !wait_result {
            return Ok(SendSmsResult {
                success: true,
                send_result: None,
                note: None,
            });
        }

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Instant::now() >= deadline {
                return Ok(SendSmsResult {
                    success: true,
                    send_result: None,
                    note: Some("timeout in attesa dello stato".into()),
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            match self
                .call(
                    "DEV2_LTE_SMS_SENDNEWMSG",
                    "go",
                    json!({"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}),
                )
                .await
            {
                Ok(status) => {
                    let data = status.get("data").cloned().unwrap_or(Value::Null);
                    if let Some(sr) = str_field(&data, "sendResult")
                        && sr != "3"
                        && sr != "0"
                    {
                        return Ok(SendSmsResult {
                            success: true,
                            send_result: Some(sr),
                            note: None,
                        });
                    }
                }
                Err(ArcherError::SessionExpired(_)) => {
                    return Ok(SendSmsResult {
                        success: true,
                        send_result: None,
                        note: Some(
                            "SMS inviato, ma la sessione è scaduta durante l'attesa della conferma di consegna \
                             (esito finale non verificato)"
                                .into(),
                        ),
                    });
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Info SIM/rete/consumo dati. Gli OID richiedono stack "1,0,0,0,0,0"
    /// (indice di istanza 1: gli oggetti SMS usano invece "0,0,0,0,0,0" -
    /// senza questo dettaglio il router risponde errorcode 9003).
    pub async fn sim_info(&mut self) -> Result<SimInfo, ArcherError> {
        let instance1 = json!({"stack": "1,0,0,0,0,0", "pstack": "0,0,0,0,0,0"});
        let usim = self
            .call("DEV2_CELL_INTF_USIM", "go", instance1.clone())
            .await?;
        let net_status = self
            .call("DEV2_LTE_NET_STATUS", "go", instance1.clone())
            .await?;
        let link_cfg = self
            .call("DEV2_LTE_LINK_CFG", "go", instance1.clone())
            .await?;
        let traffic = self.call("DEV2_XTP_LTE_INTF_CFG", "go", instance1).await?;

        let u = usim.get("data").cloned().unwrap_or(Value::Null);
        let n = net_status.get("data").cloned().unwrap_or(Value::Null);
        let l = link_cfg.get("data").cloned().unwrap_or(Value::Null);
        let t = traffic.get("data").cloned().unwrap_or(Value::Null);

        let total_bytes = num_field(&t, "totalStatistics").unwrap_or(0.0);
        let daily_bytes = num_field(&t, "dailyFlow").unwrap_or(0.0);

        Ok(SimInfo {
            iccid: str_field(&u, "ICCID"),
            imsi: str_field(&u, "IMSI"),
            msisdn: str_field(&u, "MSISDN"),
            sim_status: str_field(&u, "status"),
            signal_strength: str_field(&n, "sigLevel"),
            sms_center: str_field(&l, "smsScAddress"),
            ipv4: str_field(&l, "ipv4"),
            ipv6: str_field(&l, "ipv6"),
            dns: vec![str_field(&l, "dns1v4"), str_field(&l, "dns2v4")],
            connected_bands: str_field(&l, "connectedBand"),
            roaming: str_field(&l, "roamingStatus").as_deref() == Some("1"),
            total_used_gb: round_to(total_bytes / 1024f64.powi(3), 1000.0),
            today_used_mb: round_to(daily_bytes / 1024f64.powi(2), 10.0),
            data_limit_enabled: str_field(&t, "enableDataLimit").as_deref() == Some("1"),
            data_limit_bytes: str_field(&t, "dataLimit"),
        })
    }
}

fn extract_jsessionid(resp: &reqwest::Response) -> Option<String> {
    for value in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let s = value.to_str().ok()?;
        if let Some(rest) = s.strip_prefix("JSESSIONID=") {
            let end = rest.find(';').unwrap_or(rest.len());
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

fn int_field(v: &Value, key: &str) -> Option<i64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn num_field(v: &Value, key: &str) -> Option<f64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn round_to(x: f64, factor: f64) -> f64 {
    (x * factor).round() / factor
}

// --------------------------------------------------------------------- //
// Sessione con stato: login lazy + retry-on-session-expired
// --------------------------------------------------------------------- //

pub struct ArcherSession {
    config: ArcherConfig,
    client: Mutex<Option<ArcherClient>>,
}

impl ArcherSession {
    pub fn new(config: ArcherConfig) -> Self {
        Self {
            config,
            client: Mutex::new(None),
        }
    }

    /// Se manca un client autenticato in cache, ne crea uno nuovo e fa
    /// login. Ritorna un errore direttamente utilizzabile con `?`.
    async fn ensure_logged_in(&self, slot: &mut Option<ArcherClient>) -> Result<(), ArcherError> {
        if slot.is_none() {
            let mut c = ArcherClient::new(
                &self.config.url,
                &self.config.username,
                self.config.trust_all_certs,
            )?;
            c.login(&self.config.password).await?;
            *slot = Some(c);
        }
        Ok(())
    }

    pub async fn inbox(&self, page: u32) -> Result<InboxPage, ArcherError> {
        let mut guard = self.client.lock().await;
        self.ensure_logged_in(&mut guard).await?;
        match guard.as_mut().unwrap().inbox(page).await {
            Err(ArcherError::SessionExpired(_)) => {
                *guard = None;
                self.ensure_logged_in(&mut guard).await?;
                guard.as_mut().unwrap().inbox(page).await
            }
            other => other,
        }
    }

    pub async fn sim_info(&self) -> Result<SimInfo, ArcherError> {
        let mut guard = self.client.lock().await;
        self.ensure_logged_in(&mut guard).await?;
        match guard.as_mut().unwrap().sim_info().await {
            Err(ArcherError::SessionExpired(_)) => {
                *guard = None;
                self.ensure_logged_in(&mut guard).await?;
                guard.as_mut().unwrap().sim_info().await
            }
            other => other,
        }
    }

    /// Vedi il commento su [`ArcherClient::send_sms`]: una `SessionExpired`
    /// qui può capitare solo *prima* che l'SMS sia stato accodato con
    /// successo (il caso "dopo" è già gestito internamente), quindi
    /// ritentare l'intera operazione è sicuro.
    pub async fn send_sms(
        &self,
        to: &str,
        text: &str,
        wait_result: bool,
    ) -> Result<SendSmsResult, ArcherError> {
        let mut guard = self.client.lock().await;
        self.ensure_logged_in(&mut guard).await?;
        match guard
            .as_mut()
            .unwrap()
            .send_sms(to, text, wait_result)
            .await
        {
            Err(ArcherError::SessionExpired(_)) => {
                *guard = None;
                self.ensure_logged_in(&mut guard).await?;
                guard
                    .as_mut()
                    .unwrap()
                    .send_sms(to, text, wait_result)
                    .await
            }
            other => other,
        }
    }
}
