# Protocollo del pannello TP-Link Archer (serie SIM 4G/5G, "GDPR encrypt")

Ricostruito con reverse engineering (analisi statica di `js/tpEncrypt.js`,
`js/gdprProxy.js`, `js/encrypt.js`, `js/lib.js`, `js/oid_str.js` della WebUI,
e cattura/verifica del traffico reale generato dal browser) contro un
**Archer NX200** (5G AX1800), firmware `1.2.0 3.0.0 v60e0.0 Build 250725
Rel.73467n`. Lo schema crittografico e di sessione è comune a diversi router
Archer con questa WebUI ("GDPR encrypt"); i nomi degli OID applicativi (SMS,
LTE, ecc.) sono specifici del modulo LTE/5G e vanno riverificati su modelli
diversi.

## 1. Panoramica

Tutte le operazioni autenticate (lettura/scrittura di qualunque dato:
elenco SMS, invio SMS, stato rete, ecc.) passano da un **unico endpoint**:

```
POST /cgi_gdpr?9
Content-Type: text/plain

sign=<firma RSA, hex>\r\n
data=<payload cifrato AES-128-CBC, base64>\r\n
```

Il corpo della risposta è la sola stringa base64 del payload cifrato con
AES (nessun wrapping `sign=`/`data=` in risposta). Il payload in chiaro,
sia in richiesta che in risposta, è un oggetto JSON compatto (nessuno spazio
extra, come prodotto da `JSON.stringify`) del tipo:

```json
{"data": {"...": "..."}, "operation": "so|go|gl|cgi", "oid": "NOME_OID"}
```

- `operation`: `"go"` = get (leggi), `"so"` = set (scrivi/imposta un
  parametro), `"gl"` = get list (leggi una lista di elementi), `"cgi"` =
  invoca un endpoint speciale per `oid` (usato solo dal login).
- `oid`: nome simbolico dell'oggetto dati (es. `DEV2_LTE_SMS_RECVMSGENTRY`),
  oppure il path `/cgi/login` per il login.
- `data`: i parametri della chiamata. Include quasi sempre `"stack"` e
  `"pstack"`, due stringhe tipo `"0,0,0,0,0,0"` che indicizzano
  l'istanza dell'oggetto nel modello dati interno del router (vedi §5).

Non esiste **nessun endpoint di "solo lettura senza autenticazione"** oltre
a `/cgi/getGDPRParm` (bootstrap RSA) e `/cgi/getBusy` (stato "qualcuno è
loggato?"): tutto il resto richiede l'handshake completo descritto sotto.

## 2. Handshake di login

### 2.1 Bootstrap RSA — `POST /cgi/getGDPRParm` (non autenticato)

Richiesta: `POST` con corpo vuoto. Risposta: testo JavaScript "eval-abile"
(non JSON), ad es.:

```js
var adminSetting=0;
var userSetting=1;
var logoUrl="";
var ee="010001";
var nn="D9FEB17A22CF0C147D4A1939A7A108B71A0F9E25AC9062084C2FD2A19FC11A875969B9D1124A943BD72B9CB351D3197245995CE4555B0481C55F4DBAECBCF271";
var seq="1049343027";
$.ret=0;
```

- `nn`/`ee`: modulo ed esponente pubblico RSA, **512 bit** (128 caratteri
  hex), esponente tipicamente `010001` (65537).
- `seq`: intero usato come base del contatore anti-replay. **Resta fisso
  per tutta la sessione**: non va richiesto di nuovo per le chiamate
  successive al login (il client originale lo rilegge solo perché ricarica
  l'intera pagina dopo il login, non perché serva un valore nuovo).

### 2.2 Cifratura del payload di login

1. Si genera una chiave AES-128 e un IV, **16 byte ASCII qualunque**
   ciascuno (il client originale usa cifre di `timestamp + random`, ma
   qualunque stringa di 16 byte va bene: la chiave viene comunque scambiata
   cifrata via RSA e usata solo per questa sessione).
2. `hash = MD5(username + password)`, esadecimale minuscolo. `username` di
   **default è `"user"`**, non `"admin"`: sull'Archer NX200 (e sui modelli
   con `INCLUDE_USER_RESTRICTION=1` e senza campo username nella GUI di
   login) l'account a cui corrisponde la password del pannello è quello
   "user" (`adminType="user"` nella pagina), non "admin" — verificato:
   `MD5("user"+password)` combacia esattamente con l'hash usato dal client
   reale.
3. Payload in chiaro:
   ```json
   {"data": {"UserName": "<base64(username)>", "Passwd": "<base64(password)>",
             "Action": "1", "stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"},
    "operation": "cgi", "oid": "/cgi/login"}
   ```
4. `cipher_b64 = AES-128-CBC-PKCS7(payload_json, key, iv)`, poi base64.
5. Firma: stringa da firmare =
   `"key=<key>&iv=<iv>&h=<hash>&s=<seq + lunghezza in caratteri di cipher_b64>"`.
   **Nota**: `s` non è semplicemente `seq`, ma `seq + len(cipher_b64)`, e
   questo calcolo si ripete per ogni chiamata (vedi §3); `seq` stesso però
   non cambia mai nell'ambito della sessione.
6. `sign = RSA_raw_no_padding(stringa_da_firmare, nn, ee)` (vedi §4).
7. Corpo HTTP: `"sign=" + sign + "\r\ndata=" + cipher_b64 + "\r\n"`, inviato
   in `POST /cgi_gdpr?9` con `Content-Type: text/plain`.

### 2.3 Risposta al login

- **HTTP 200**, header `Set-Cookie: JSESSIONID=<30 caratteri hex>; Path=/;
  HttpOnly` (vedi §6.1).
- Corpo: base64 AES che decifra (con la stessa key/iv scelte al passo 1) in
  `"$.ret=0;"` seguito talvolta da un byte NUL (`\x00`) di riempimento — va
  scartato, non è parte del messaggio. `$.ret=0` indica successo; altri
  codici indicano credenziali errate o altri problemi (non mappati in
  dettaglio: si consideri qualunque valore diverso da 0 come fallimento).

Da qui in poi **key/iv/hash/seq restano fissi per tutta la sessione**: le
chiamate successive non li ritrasmettono (eccetto seq, indirettamente, nel
calcolo di `s`).

## 3. Chiamate dati post-login

Stesso schema di trasporto (`POST /cgi_gdpr?9`, corpo `sign=...&data=...`),
ma:

- **Payload**: `{"data": {...}, "operation": "so"|"go"|"gl", "oid": "..."}`
  (niente più `UserName`/`Passwd`/`Action`).
- **Firma**: la stringa da firmare è solo `"h=<hash>&s=<seq+len(cipher_b64)>"`
  — **senza** `key=`/`iv=` (il server li ricorda già dalla sessione).
  Verificato byte-per-byte: per un input reale la firma RSA calcolata con
  questo schema coincide esattamente con quella prodotta dal client JS.
- La risposta decifra in JSON "vero" (spaziato, non compatto):
  `{"data": {...}, "operation": "...", "oid": "...", "success": true|false[,
  "errorcode": N]}`.

### 3.1 Header obbligatori sulle chiamate dati (la parte più insidiosa)

Oltre al corpo firmato, **due elementi non documentati nei sorgenti JS
statici** sono necessari o il router risponde `406 Not Acceptable` a
qualunque chiamata `so`/`go`/`gl` (il login da solo funziona anche senza):

1. **Cookie `JSESSIONID`** ricevuto al login (§2.3). È marcato `HttpOnly`:
   **invisibile a `document.cookie` lato browser** (per questo un'analisi
   che si limiti a ispezionare `document.cookie` conclude erroneamente che
   il pannello "non usa cookie"). Va letto dagli header HTTP grezzi della
   risposta di login e rimandato indietro in `Cookie: JSESSIONID=...` su
   ogni richiesta successiva.
2. **Header `TokenID`**, un secondo token di sessione (30 caratteri hex,
   stesso formato del JSESSIONID ma un valore diverso e indipendente) che
   il router **incorpora lato server nell'HTML della home page**, in un
   tag tipo:
   ```html
   <script type="text/javascript">var token="63d8d4da2e53f658fbd9a0f76aaf7e";</script>
   ```
   Questo script è generato **solo se la richiesta a `GET /` porta un
   cookie `JSESSIONID` valido** (con una sessione anonima non compare
   affatto) — per questo non si trova mai cercando "tokenid" nei file `.js`
   statici: non è mai assegnato lì, viene iniettato dal server nell'HTML
   per sessione. Va quindi: fare login → **fare un `GET /` con il cookie di
   sessione** → estrarre `token` con una regex tipo
   `var\s+token\s*=\s*"([0-9a-fA-F]+)"` → usarlo come header
   `TokenID: <token>` su tutte le chiamate successive.

   Verificato sperimentalmente (dal contesto della pagina autenticata, non
   per deduzione): con l'header `TokenID` corretto la chiamata risponde
   `200`; con `TokenID: 0` (o assente, o un valore auto-generato a caso ma
   coerente) risponde **sempre** `406`, indipendentemente da firma/oid/dati.

Senza nessuno dei due, il comportamento osservato è **inconsistente**: a
seconda dei casi il router risponde con un pulito `406`, oppure chiude la
connessione a metà (`Empty reply from server` / `Connection reset`) — un
comportamento tipico di un bug del backend embedded quando riceve richieste
"strutturalmente valide ma non autorizzate", non un errore applicativo
pulito. Non affidarsi al codice di errore per capire cosa manca: se una
chiamata post-login fallisce sempre indipendentemente da oid/dati/firma, il
sospetto numero uno è cookie o token mancanti/scaduti.

## 4. Firma RSA "raw" senza padding

Il client (libreria `jsbn` inclusa in `js/encrypt.js`) usa RSA a 512 bit
**senza padding PKCS#1**:

1. Il messaggio da firmare viene preso come byte UTF-8.
2. Viene troncato in blocchi da **64 byte** (512 bit / 8: la dimensione del
   modulo). Per le firme usate qui (poche decine di caratteri per le
   chiamate dati, ~90 per il login) è quasi sempre **1 blocco** (dati) o
   **2 blocchi** (login, per via del prefisso `key=...&iv=...`).
3. Ogni blocco viene riempito con **byte zero a destra** fino a 64 byte
   (non un padding crittografico: letteralmente zeri).
4. Il blocco riempito è interpretato come **intero big-endian non
   firmato** (`m`).
5. `c = m^e mod n`.
6. `c` è stampato in esadecimale e **zero-paddato a sinistra a 128
   caratteri** (64 byte) per blocco.
7. I blocchi (se più di uno) sono concatenati in ordine.

In Python: `pow(int.from_bytes(chunk_paddato, "big"), e, n)`, formattato
`"%0128x"`. In Java: `new BigInteger(1, chunk).modPow(e, n)` (il flag di
segno `1` = magnitudine positiva, equivalente all'`int.from_bytes` non
firmato di Python — **non** usare il costruttore `BigInteger(byte[])` a un
solo argomento, che tratta il primo bit come segno in complemento a due).

Il router **non richiede alcun padding PKCS#1** in ricezione: usa
esattamente questo schema anche lato server per decifrare la firma.

## 5. AES-128-CBC e il modello dati "stack"

- AES-128-CBC, padding PKCS7 (in Java: `"AES/CBC/PKCS5Padding"`, che per
  AES è lo stesso algoritmo). Chiave e IV sono i 16 byte ASCII scelti al
  login, usati **direttamente** come materiale della chiave (nessun KDF).
- Il modello dati del router è quello classico CWMP/TR-069: gli oggetti
  sono "istanze" indicizzate da uno `"stack"` a 6 componenti separate da
  virgola (`"a,b,c,d,e,f"`), tutte `0` di default. **Molti oggetti LTE
  richiedono `stack: "1,0,0,0,0,0"`** (istanza 1) e **non**
  `"0,0,0,0,0,0"`: usare lo stack sbagliato produce quasi sempre
  `{"success": false, "errorcode": 9003}` (istanza non trovata), non un
  errore di trasporto. Gli oggetti SMS osservati usano invece
  `"0,0,0,0,0,0"` per l'oggetto principale (`RECVMSGBOX`, `SENDNEWMSG`) ma
  ancora `"0,0,0,0,0,0"` per la getlist delle entry (`RECVMSGENTRY`) — non
  c'è una regola unica: **va verificato per singolo OID** osservando il
  traffico reale.
- Pattern "set poi get": per molte letture paginate/con parametri (es. la
  posta in arrivo) il client fa prima una `"so"` per impostare un parametro
  (es. `PageNumber`) sull'oggetto, poi una `"go"`/`"gl"` per leggerne il
  risultato — sono due chiamate separate, non una sola.

## 6. Sessione e limiti

### 6.1 Nessun vero controllo di accesso "a richiesta"

A parte cookie+token (verificati solo per accettare/rifiutare una singola
richiesta), il router **non implementa una sessione per-client** in senso
stretto: ammette **una sola sessione amministrativa attiva alla volta**
("Può fare login un solo dispositivo alla volta" nella GUI). Un nuovo login
**prende automaticamente il posto** di quello precedente — via script,
senza alcuna conferma richiesta (la finestra "vuoi forzare il logout
dell'altro dispositivo?" è puro zucchero della GUI lato client: la
richiesta HTTP di login è identica sia che l'utente clicchi "conferma" sia
che non ci sia nessun altro loggato). Conseguenza pratica: se si esegue uno
script e poi ci si logga dalla GUI (o viceversa), la sessione precedente
viene sostituita e occorre eventualmente confermare a mano il popup lato
GUI.

Non è stato individuato un endpoint di logout esplicito (non compare nei
file `.js` statici: il gestore del pulsante "Logout" fa parte di contenuto
caricato/decifrato dinamicamente dopo il login, non ispezionato). In pratica
non è necessario: la sessione seguente prende comunque il posto di quella
attiva.

**Nota pratica confermata**: tenere aperta la GUI del router in un browser
(anche solo sulla pagina di login, non serve essere autenticati) mentre un
client automatizzato (script o processor NiFi) tenta il login può causare
fallimenti intermittenti — inclusi `406` su endpoint non autenticati come
`/cgi/getGDPRParm` — perché il client automatizzato finisce a contendersi lo
slot di sessione con il polling in background della pagina del browser.
Chiudere la scheda del browser risolve il problema. Se si esegue un client
automatizzato su un ciclo/scheduling ravvicinato (es. un processor NiFi con
scheduling a intervallo troppo corto o "Concurrent Tasks" > 1), lo stesso
tipo di conflitto può presentarsi anche fra esecuzioni consecutive del
client stesso: il webserver embedded del router regge male richieste di
login troppo ravvicinate/parallele.

### 6.2 Bug del webserver embedded sul riuso della connessione

Il webserver del router **non gestisce correttamente il keep-alive HTTP**
quando il corpo della richiesta contiene sequenze CRLF letterali (come nel
formato `"sign=...\r\ndata=...\r\n"` usato qui): riusare la stessa
connessione TCP per due richieste consecutive a `/cgi_gdpr` produce spesso
un `406` o la chiusura brusca della connessione, **anche con payload
altrimenti corretto**. Va aperta una connessione TCP/TLS nuova per ogni
richiesta (vedi implementazioni: `requests.Session()` per chiamata in
Python, un `HttpClient` per chiamata in Java).

### 6.3 Certificato TLS

Il pannello espone HTTPS con un certificato **autofirmato e senza alcun
subject/SAN** (`subject: [NONE]`, CN dell'emittente tipo `TP-LINK SOHO
Router CA`). Qualunque client deve disabilitare sia la verifica della
catena di trust sia la verifica del nome host (non basta un semplice
"ignora errori di trust": va disattivata anche l'hostname verification, o
l'handshake TLS fallisce comunque per mismatch di nome).

## 7. OID verificati

Tutti confermati contro traffico reale (decifrato con la chiave di sessione
osservata) o contro risposte dirette del router via lo stesso schema.

| OID | operation | stack | Note |
|---|---|---|---|
| `/cgi/login` | `cgi` | `0,0,0,0,0,0` | Solo per il login (§2). |
| `DEV2_LTE_SMS_RECVMSGBOX` | `so` poi `go` | `0,0,0,0,0,0` | `so`: imposta `PageNumber`. `go`: ritorna `totalNumber`, `unreadNumber`, `pageNumber`, `amountPerPage`. |
| `DEV2_LTE_SMS_RECVMSGENTRY` | `gl` | `0,0,0,0,0,0` | Ritorna un array di `{index, from, content, receivedTime, unread, stack}`: gli SMS della pagina corrente. |
| `DEV2_LTE_SMS_UNREADMSGBOX` / `_UNREADMSGENTRY` | come sopra | `0,0,0,0,0,0` | Solo i non letti (usato dal widget dashboard). |
| `DEV2_LTE_SMS_SENDNEWMSG` | `so` poi `go` | `0,0,0,0,0,0` | `so`: `{index:"1", to, textContent}` → `{"success":true,"errorcode":0}`. `go` (polling): `{index, to, textContent, sendTime, sendResult, stack}`; `sendResult`: `"3"` = invio in corso, `"1"` = inviato con successo (altri valori non mappati = probabile errore). |
| `DEV2_CELL_INTF_USIM` | `go` | **`1,0,0,0,0,0`** | `{status, IMSI, ICCID, MSISDN, PINCheck, PIN}`. |
| `DEV2_LTE_NET_STATUS` | `go` | **`1,0,0,0,0,0`** | `{sigLevel, connStat, roamStat, regStat, netType, srvStat, smsUnreadCount, ...}`. |
| `DEV2_LTE_LINK_CFG` | `go` | **`1,0,0,0,0,0`** | Connessione dati: `ipv4/ipv6`, `dns1v4/dns2v4`, `gatewayV4/V6`, `connectedBand`/`availableBand`, `roamingStatus`, `smsScAddress` (centro SMS), `signalStrength`. |
| `DEV2_XTP_LTE_INTF_CFG` | `go` | **`1,0,0,0,0,0`** | Contatori dati: `totalStatistics` e `dailyFlow` (**byte**, non GB — dividere per 1024³ per i GB mostrati in GUI), `rxFlow`/`txFlow`, `enableDataLimit`/`dataLimit`/`limitType`/`limitation`/`warningPercent` (soglia di allarme dati, se configurata). |
| `DEV2_XTP_LTE` | `go` | `0,0,0,0,0,0` | Info modulo modem: produttore, seriale, versione firmware del modulo LTE. |
| `DEV2_LTE_ISP_PROF` | `gl` | `0,0,0,0,0,0` | Elenco profili APN preconfigurati per operatore (non il profilo attivo). |
| `DEV2_LTE_BANDINFO` | `go` | `0,0,0,0,0,0` | Banda/canale radio attivi (valori osservati a "0" a riposo). |

OID **tentati e risultati in errore** (`errorcode 9003`, "istanza non
trovata") con `stack:"0,0,0,0,0,0"` — quasi certamente richiedono uno stack
diverso non ancora determinato, non sono inutilizzabili in assoluto:
`DEV2_LTE_SERVING_CELL_INFO`, `DEV2_LTE_PROF_STAT`, `DEV2_LTE_PROFILE`,
`DEV2_LTE_ISP_PROF` (con `go` invece di `gl`).

**Attenzione**: chiamare un oid/operazione non valido per il router non
sempre produce un errore applicativo pulito — in alcuni casi osservati ha
causato la chiusura brusca della connessione (probabile crash del processo
CGI di backend che gestisce quella specifica richiesta, non solo un rifiuto
a livello protocollo). Va quindi validato ogni nuovo OID con cautela,
idealmente osservando prima il traffico reale generato dalla GUI per quella
funzione invece di tentativi alla cieca.

## 8. Cosa NON è stato determinato

- L'endpoint/formato esatto del **logout esplicito** (§6.1) — non
  necessario in pratica, ma non mappato.
- Lo `stack` corretto per `DEV2_LTE_SERVING_CELL_INFO` (banda/cella
  servente in dettaglio: RSRP/RSRQ/SINR precisi come mostrati in GUI) e per
  gli altri OID elencati come falliti al §7.
- Il significato completo dei codici `sendResult` di `DEV2_LTE_SMS_SENDNEWMSG`
  oltre a `"3"` (in corso) e `"1"` (successo osservato).
- Se/come un `PIN` SIM venga gestito da `DEV2_CELL_INTF_USIM` (il campo
  esiste, `PINCheck` era `"Off"` sul dispositivo di test — non testato con
  PIN attivo).

## 9. Riferimenti nel repository

- `archer_sms.py` — client Python di riferimento (login, `inbox`, `send`,
  `siminfo`), CLI pronta all'uso.
- `nifi-archer-router/` — bundle Maven per Apache NiFi 2.x con lo stesso
  client riscritto in Java (`ArcherCrypto`, `ArcherClient`) e il processor
  `InvokeArcherRouter`.
