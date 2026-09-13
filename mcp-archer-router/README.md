# mcp-archer-router

Server [MCP](https://modelcontextprotocol.io) (stdio) **e/o** API REST (JSON
su HTTP) per il pannello di gestione dei router TP-Link Archer con SIM 4G/5G
(firmware "GDPR encrypt", testato su **Archer NX200**). Stesse funzionalità
di `archer_sms.py` e del processor NiFi in `nifi-archer-router/`: lettura
della posta in arrivo SMS, invio SMS, info SIM/rete/consumo dati —
riprodotte in Rust senza dipendenze esterne oltre alle librerie di sistema.

Vedi `PROTOCOL.md` nella root del repository per la descrizione completa del
protocollo.

## Transport: MCP, REST, o entrambi

I due transport si accendono/spengono indipendentemente (`ARCHER_MCP_ENABLED`
/ `ARCHER_REST_ENABLED`, vedi Configurazione) e, quando sono attivi insieme,
condividono **la stessa sessione** verso il router (stesso login in cache):
il router ne accetta una sola alla volta, quindi non avrebbe senso farne
autenticare due indipendenti l'uno dall'altro. Ogni errore verso il router,
su entrambi i transport, viene loggato (livello ERROR) su stderr prima di
essere tradotto nella risposta all'MCP client o nel body JSON REST.

### Tool / endpoint esposti

| Tool MCP | Endpoint REST | Descrizione |
|---|---|---|
| `sms_inbox` | `GET /sms/inbox?page=0` | Elenca gli SMS in posta in arrivo. `page` opzionale, 0-based, default 0. |
| `sms_send` | `POST /sms/send` (body `{"to","text","wait_result"?}`) | Invia un SMS. `wait_result` default `true`: attende fino a 20s l'esito. |
| `sim_info` | `GET /sim/info` | ICCID/IMSI, segnale, IP assegnato, consumo dati totale/odierno. |
| — | `GET /health` | Health check statico (non tocca il router), per readiness probe. |

Il REST non ha **nessuna autenticazione**: pensato per essere esposto solo su
`localhost` o su una rete già fidata (default `ARCHER_REST_BIND=127.0.0.1:...`
— cambialo solo se sai cosa comporta esporlo altrove). Un errore verso il
router diventa sempre `502 Bad Gateway` con body `{"error": "..."}`; una
richiesta malformata (JSON invalido, campo mancante) è già intercettata da
`axum` prima di arrivare al router, con `400`/`422`.

## Sessione

Login **lazy**: la prima chiamata a un tool autentica e mette in cache
cookie di sessione + token CSRF; le chiamate successive riusano la sessione.
Se il router segnala che la sessione non è più valida (tipicamente perché
qualcun altro si è loggato nel frattempo, es. dalla GUI del browser — il
router accetta una sola sessione amministrativa alla volta, vedi
PROTOCOL.md §6.1), il server si ri-autentica e ritenta automaticamente
l'operazione **una volta**, tranne per `sms_send`: se la sessione scade
*durante* l'attesa dell'esito (cioè dopo che l'SMS è già stato accodato con
successo), l'operazione non viene ripetuta per evitare un invio duplicato —
il tool ritorna comunque `success: true` con una nota che l'esito finale non
è stato confermato.

Tutte le chiamate condividono un'unica sessione dietro un lock: non c'è
concorrenza reale verso il router, che comunque non la supporterebbe (una
sola sessione alla volta).

## Configurazione

Variabili d'ambiente:

| Variabile | Default | Note |
|---|---|---|
| `ARCHER_ROUTER_URL` | `https://192.168.10.1` | URL base del pannello. |
| `ARCHER_USERNAME` | `user` | Su modelli come l'NX200, senza campo username in GUI, è `"user"` e non `"admin"`. |
| `ARCHER_PASSWORD` | *(obbligatoria)* | Password del pannello. |
| `ARCHER_TRUST_ALL_CERTS` | `true` | Il pannello usa un certificato TLS autofirmato senza subject/SAN (vedi PROTOCOL.md §6.3): lasciare `true` a meno di aver installato un certificato valido. |
| `ARCHER_MCP_ENABLED` | `true` | Server MCP su stdio. |
| `ARCHER_REST_ENABLED` | `false` | API REST JSON su HTTP (vedi sopra). |
| `ARCHER_REST_BIND` | `127.0.0.1:8787` | Indirizzo:porta di ascolto REST, solo se `ARCHER_REST_ENABLED=true`. |

Almeno uno tra `ARCHER_MCP_ENABLED` e `ARCHER_REST_ENABLED` deve restare
`true`, altrimenti il processo si rifiuta di partire (log d'errore + exit
non-zero).

## Build

```
cargo build --release
```

Produce un binario nativo autocontenuto in `target/release/mcp-archer-router`
(TLS via `rustls`, non OpenSSL/native-tls: su macOS le uniche dipendenze
dinamiche sono le librerie di sistema — verificabile con `otool -L`, su
Linux con `ldd`).

## Configurazione in un client MCP

Esempio per un client che legge un file `mcp.json`/`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "archer-router": {
      "command": "/percorso/a/target/release/mcp-archer-router",
      "env": {
        "ARCHER_ROUTER_URL": "https://192.168.10.1",
        "ARCHER_USERNAME": "user",
        "ARCHER_PASSWORD": "***"
      }
    }
  }
}
```

## Stato

Compila, esegue i test crittografici (`cargo test`: MD5, AES-128-CBC, firma
RSA raw verificati contro vettori noti/una chiave di test) ed è **verificato
end-to-end contro un Archer NX200 reale**, con credenziali corrette:
handshake RSA/AES-128-CBC, sessione (JSESSIONID + TokenID), login,
`sim_info` e `sms_inbox` restituiscono dati reali dal router, su entrambi i
transport (MCP via JSON-RPC su stdio, REST via HTTP), singolarmente e
insieme, incluso `sms_send` (esempio dedicato `send_test_sms.rs`, separato
da `live_check.rs` che resta di sola lettura): SMS inviato con successo,
`sendResult: "1"` confermato dal router. Non ancora esercitato: il retry
automatico su sessione scaduta/rubata (richiederebbe un secondo login
concorrente, es. dalla GUI, durante un test).
