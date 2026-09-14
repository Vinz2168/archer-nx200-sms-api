# archer-nx200-sms-api

Reverse engineering (non documentazione ufficiale) del protocollo usato
dalla WebUI dei router TP-Link Archer con SIM 4G/5G, firmware "GDPR
encrypt" (testato su un **Archer NX200**, 5G AX1800), e sua reimplementazione
in più linguaggi/target per leggere/inviare SMS e leggere info SIM/rete/
consumo dati senza passare dal browser.

Il protocollo (handshake RSA 512 bit + AES-128-CBC, gestione sessione
JSESSIONID/TokenID, elenco degli OID applicativi verificati, limitazioni
note) è documentato per intero in **[`PROTOCOL.md`](PROTOCOL.md)**: è il
riferimento comune a tutte le implementazioni sotto, non ce n'è una
copia per linguaggio.

## Cosa c'è nel repo

| | Linguaggio | Cosa fa |
|---|---|---|
| [`archer_sms.py`](archer_sms.py) | Python | Client CLI di riferimento: prima implementazione del protocollo, usata per verificarlo. |
| [`nifi-archer-router/`](nifi-archer-router/) | Java | Processor Apache NiFi 2.x (`InvokeArcherRouter`) per integrare il pannello in una pipeline NiFi. |
| [`mcp-archer-router/`](mcp-archer-router/) | Rust | Server [MCP](https://modelcontextprotocol.io) (stdio) e/o API REST, per usare il pannello da un agente/LLM o via HTTP. Binario nativo autocontenuto. |

Tutte e tre le implementazioni coprono le stesse operazioni (login, lettura
posta in arrivo SMS, invio SMS, info SIM/rete/consumo dati) con lo stesso
comportamento verso il router: username di default `"user"` (non
`"admin"`), certificato TLS autofirmato da accettare esplicitamente, e la
stessa regola pratica sulla sessione — **il router accetta una sola
sessione amministrativa alla volta**: un nuovo login (da script o da un
altro client, incluso il browser) scavalca silenziosamente quello
precedente, senza conferma. Tenere aperta la GUI mentre gira un client
automatizzato causa fallimenti intermittenti (vedi `PROTOCOL.md` §6.1).
Il processor NiFi e il server Rust gestiscono questo caso con un retry
automatico su sessione scaduta (tranne per l'invio SMS, per evitare un
doppio invio se la sessione cade a metà del polling dell'esito); il client
Python è pensato per un singolo comando una tantum e non lo fa.

Ognuna delle tre directory ha il proprio README con istruzioni di build e
uso specifiche del linguaggio/target.

## Stato

Verificato end-to-end contro un Archer NX200 reale, con credenziali
corrette: login, `sim_info`, `sms_inbox` e `sms_send` funzionano su tutte
le implementazioni. Non ancora esplorato: il firmware del router (per
capire come sono gestiti utenti/permessi oltre a `user`/`admin`) — vedi
`PROTOCOL.md` §8 per le lacune note.

## Uso responsabile

Questo repository è il risultato di reverse engineering della WebUI del
proprio router, a scopo di interoperabilità e automazione personale (es.
integrare gli SMS di una SIM 4G/5G in una pipeline domestica). Non è
software ufficiale TP-Link e non implica alcuna garanzia: usalo solo contro
router di cui hai la proprietà/autorizzazione e le credenziali legittime.
