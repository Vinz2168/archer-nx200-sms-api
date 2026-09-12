package com.archer.nifi.processors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client per il pannello di gestione dei router TP-Link Archer con SIM
 * 4G/5G (firmware "GDPR encrypt", testato su Archer NX200): riproduce il
 * protocollo della WebUI senza passare dal browser.
 *
 * <p>Vedi PROTOCOL.md nel repository per la descrizione completa, ricostruita
 * con reverse engineering (analisi di js/tpEncrypt.js, js/gdprProxy.js,
 * js/encrypt.js e cattura del traffico reale). Riassunto essenziale:</p>
 *
 * <ol>
 *   <li>GET/POST {@code /cgi/getGDPRParm} (non autenticato) restituisce
 *       modulo/esponente RSA a 512 bit ("nn"/"ee") e un nonce di sessione
 *       "seq" che resta fisso per tutta la sessione.</li>
 *   <li>Login: JSON {@code {"data":{...UserName/Passwd in base64...},
 *       "operation":"cgi","oid":"/cgi/login"}} cifrato AES-128-CBC con una
 *       chiave di sessione generata dal client; la chiave stessa viene
 *       trasmessa cifrata con RSA "raw" (nessun padding) insieme a
 *       {@code MD5(username+password)} e a "seq". Il corpo HTTP è
 *       {@code "sign=<firma RSA hex>\r\ndata=<AES base64>\r\n"} in POST su
 *       {@code /cgi_gdpr?9}.</li>
 *   <li>Il router risponde con un cookie {@code JSESSIONID} HttpOnly (va
 *       quindi letto dagli header HTTP grezzi, non da document.cookie/JS) e,
 *       se si richiede la home page ("/") con quel cookie, la risposta
 *       contiene {@code <script>var token="...";</script>}: questo valore va
 *       rimandato indietro nell'header {@code TokenID} di ogni chiamata
 *       successiva, altrimenti il router risponde "406 Not Acceptable" a
 *       qualunque operazione di lettura/scrittura dati (il login funziona
 *       comunque anche senza).</li>
 *   <li>Le chiamate dati successive usano lo stesso schema di cifratura, ma
 *       la firma RSA copre solo {@code "h=<hash>&s=<seq+len(cifrato)>"}
 *       (l'AES key non viene più ritrasmessa: il server la ricorda dalla
 *       sessione). Il payload è {@code {"data":{...},"operation":
 *       "so"|"go"|"gl","oid":"<NOME_OID>"}}.</li>
 * </ol>
 *
 * <p><b>Nota sulla connessione:</b> il webserver embedded del router non
 * gestisce bene il keep-alive quando il corpo della richiesta contiene CRLF
 * letterali (come nel formato sopra): riusare la stessa connessione TCP per
 * la richiesta successiva causa risposte "406" o la chiusura brusca della
 * connessione. Questo client apre quindi un {@link HttpClient} nuovo per
 * ogni richiesta.</p>
 */
public class ArcherClient implements AutoCloseable {

    private static final String DEFAULT_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Chrome/120.0.0.0 Safari/537.36";
    private static final Pattern VAR_PATTERN = Pattern.compile("var\\s+(\\w+)\\s*=\\s*\"?([^\";]*)\"?\\s*;?");
    private static final Pattern TOKEN_PATTERN = Pattern.compile("var\\s+token\\s*=\\s*\"([0-9a-fA-F]+)\"");
    private static final Pattern SET_COOKIE_JSESSIONID = Pattern.compile("JSESSIONID=([^;]+)");

    private final String baseUrl;
    private final String username;
    private final boolean trustAllCerts;
    private final Duration requestTimeout;

    private String nn;
    private String ee;
    private long seq;
    private String hash;
    private String aesKey;
    private String aesIv;
    private String jsessionId;
    private volatile String token = "0";

    private final ObjectMapper mapper = new ObjectMapper();

    public ArcherClient(String baseUrl, String username, boolean trustAllCerts, Duration requestTimeout) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.username = username;
        this.trustAllCerts = trustAllCerts;
        this.requestTimeout = requestTimeout;
    }

    // ------------------------------------------------------------------ //
    // Basso livello
    // ------------------------------------------------------------------ //

    static {
        // Registrati una sola volta per JVM. Necessari per il motivo
        // spiegato sotto in newHttpClient(): senza il provider TLS di
        // Bouncy Castle, la JVM rifiuta di leggere il certificato del
        // router ancora prima che un TrustManager possa intervenire.
        //
        // Il provider "BC" (BouncyCastleProvider, il core JCE) va passato
        // esplicitamente al costruttore di BouncyCastleJsseProvider: senza,
        // BCJSSE delega comunque la conversione del certificato al
        // CertificateFactory X.509 di default della JVM (Sun), che è
        // altrettanto severo di quello usato dal TLS stack standard e fa
        // fallire la connessione con lo stesso errore. Con "BC" esplicito,
        // usa invece il proprio CertificateFactory X.509 (assai più
        // tollerante verso certificati non conformi a RFC 5280).
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCJSSE") == null) {
            Security.addProvider(new BouncyCastleJsseProvider(Security.getProvider("BC")));
        }
    }

    private HttpClient newHttpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(requestTimeout);
        if (trustAllCerts) {
            try {
                // Un X509TrustManager "semplice" non basta con BCJSSE: il
                // provider lo avvolge comunque in un adattatore "esteso"
                // (X509ExtendedTrustManager) che esegue in aggiunta la
                // verifica del nome host (fallisce sempre: il certificato
                // non ha alcun SAN che possa combaciare con l'IP del
                // router), indipendentemente dall'endpointIdentification-
                // Algorithm impostato sull'HttpClient. Implementando
                // direttamente X509ExtendedTrustManager (con tutti gli
                // overload, inclusi quelli con Socket/SSLEngine) e
                // lasciandoli tutti no-op, il controllo di hostname non
                // viene mai eseguito.
                TrustManager[] trustAll = new TrustManager[]{new javax.net.ssl.X509ExtendedTrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType, java.net.Socket socket) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType, java.net.Socket socket) {
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType, javax.net.ssl.SSLEngine engine) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType, javax.net.ssl.SSLEngine engine) {
                    }
                }};

                // NOTA IMPORTANTE: il certificato TLS del router è
                // autofirmato, con subject VUOTO e nessuna
                // SubjectAlternativeName. Dalla JDK usata da NiFi 2.x in poi
                // (e comunque su molte build recenti) il parser X.509 di
                // default della JVM (provider "SunJSSE"/"SUN") RIFIUTA
                // categoricamente di analizzare un certificato così fatto,
                // sollevando CertificateParsingException("subject field is
                // empty, and SubjectAlternativeName extension is absent")
                // durante l'handshake — ANCORA PRIMA che un TrustManager
                // permissivo come quello sopra venga anche solo interpellato.
                // Un TrustManager che "accetta tutto" non basta quindi a
                // risolvere il problema.
                //
                // Il fix è sostituire l'intero livello TLS della JVM con
                // quello di Bouncy Castle (provider "BCJSSE"), che ha un
                // parser X.509 più tollerante verso certificati non
                // pienamente conformi a RFC 5280, mantenendo comunque
                // l'API/SPI standard javax.net.ssl (il TrustManager sopra
                // continua a funzionare invariato).
                SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");
                sslContext.init(null, trustAll, new SecureRandom());
                builder.sslContext(sslContext);

                // Il certificato del router è autofirmato e senza alcun
                // subject/SAN valido: va disabilitata anche la verifica del
                // nome host, non solo la catena di trust.
                SSLParameters sslParameters = new SSLParameters();
                sslParameters.setEndpointIdentificationAlgorithm("");
                builder.sslParameters(sslParameters);
            } catch (Exception e) {
                throw new IllegalStateException("Impossibile configurare il contesto TLS permissivo", e);
            }
        }
        return builder.build();
    }

    /** POST grezzo con gli header comuni (User-Agent, Referer, Cookie, TokenID) e ritenta sugli errori di connessione. */
    private HttpResponse<String> post(String path, byte[] body, Map<String, String> extraHeaders) throws ArcherException {
        return send(path, "POST", HttpRequest.BodyPublishers.ofByteArray(body), extraHeaders);
    }

    /**
     * GET grezza con gli stessi header/retry di {@link #post}. Serve solo
     * per la home page ("/"): il router inietta lo script con il token di
     * sessione unicamente su una richiesta GET, non su una POST a corpo
     * vuoto (verificato: quest'ultima riceve comunque 200 ma senza lo
     * script, perché è trattata come una richiesta diversa lato server).
     */
    private HttpResponse<String> get(String path, Map<String, String> extraHeaders) throws ArcherException {
        return send(path, "GET", HttpRequest.BodyPublishers.noBody(), extraHeaders);
    }

    private static final int MAX_CONNECTION_ATTEMPTS = 4;

    // The router's embedded webserver has been observed returning a bare
    // "406 Not Acceptable" — including on unauthenticated endpoints such as
    // /cgi/getGDPRParm — apparently as a transient hiccup rather than a real,
    // persistent rejection: e.g. after the panel has sat idle for a while.
    // A single retry clears it in practice. Capped at ONE retry, and
    // deliberately kept separate from MAX_CONNECTION_ATTEMPTS: a full
    // operation (login, inbox, simInfo, ...) is made of several of these
    // calls, each with its own retry budget, so an aggressive per-call retry
    // count would multiply into a lot of extra traffic against a router that
    // is, by assumption, already struggling — the opposite of what we want.
    private static final int MAX_406_RETRIES = 1;

    private HttpResponse<String> send(String path, String method, HttpRequest.BodyPublisher bodyPublisher,
                                       Map<String, String> extraHeaders) throws ArcherException {
        Exception lastError = null;
        int retries406 = 0;
        for (int attempt = 0; attempt < MAX_CONNECTION_ATTEMPTS; attempt++) {
            try {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                        .timeout(requestTimeout)
                        .header("User-Agent", DEFAULT_UA)
                        .header("Referer", baseUrl + "/")
                        .header("TokenID", token)
                        .method(method, bodyPublisher);
                if (jessionCookie() != null) {
                    reqBuilder.header("Cookie", jessionCookie());
                }
                if (extraHeaders != null) {
                    extraHeaders.forEach(reqBuilder::header);
                }

                try (HttpClient client = newHttpClient()) {
                    HttpResponse<String> resp = client.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                    captureSessionCookie(resp);

                    if (resp.statusCode() == 406 && retries406 < MAX_406_RETRIES) {
                        retries406++;
                        sleepQuiet(1500);
                        continue;
                    }
                    return resp;
                }
            } catch (IOException | InterruptedException e) {
                lastError = e;
                sleepQuiet(300L * (attempt + 1));
            }
        }
        throw new ArcherException("Impossibile contattare il router (" + path + ")", lastError);
    }

    private String jessionCookie() {
        return jsessionId == null ? null : "JSESSIONID=" + jsessionId;
    }

    private void captureSessionCookie(HttpResponse<String> resp) {
        List<String> setCookies = resp.headers().allValues("set-cookie");
        for (String c : setCookies) {
            Matcher m = SET_COOKIE_JSESSIONID.matcher(c);
            if (m.find()) {
                this.jsessionId = m.group(1);
            }
        }
    }

    private static void sleepQuiet(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private void fetchGdprParm() throws ArcherException {
        HttpResponse<String> resp = post("/cgi/getGDPRParm", new byte[0], null);
        if (resp.statusCode() != 200) {
            throw new ArcherException("getGDPRParm ha risposto HTTP " + resp.statusCode(), null);
        }
        Map<String, String> vars = new LinkedHashMap<>();
        for (String line : resp.body().split("\\R")) {
            Matcher m = VAR_PATTERN.matcher(line.trim());
            if (m.matches()) {
                vars.put(m.group(1), m.group(2));
            }
        }
        this.nn = vars.get("nn");
        this.ee = vars.get("ee");
        String seqStr = vars.get("seq");
        if (nn == null || ee == null || seqStr == null) {
            throw new ArcherException("Risposta di getGDPRParm inattesa: " + resp.body(), null);
        }
        this.seq = Long.parseLong(seqStr);
    }

    private String signedPost(String plaintextJson, boolean isLogin) throws ArcherException {
        String cipherB64 = ArcherCrypto.aesEncrypt(plaintextJson, aesKey, aesIv);
        long sVal = seq + cipherB64.length();
        String signInput = isLogin
                ? "key=" + aesKey + "&iv=" + aesIv + "&h=" + hash + "&s=" + sVal
                : "h=" + hash + "&s=" + sVal;
        String sign = ArcherCrypto.rsaRawEncrypt(signInput, nn, ee);
        String body = "sign=" + sign + "\r\ndata=" + cipherB64 + "\r\n";

        HttpResponse<String> resp = post("/cgi_gdpr?9", body.getBytes(StandardCharsets.UTF_8),
                Map.of("Content-Type", "text/plain"));
        if (resp.statusCode() != 200) {
            throw new ArcherException("/cgi_gdpr ha risposto HTTP " + resp.statusCode()
                    + " (token/cookie di sessione mancante o scaduto?)", null);
        }
        return ArcherCrypto.aesDecrypt(resp.body(), aesKey, aesIv);
    }

    /** Chiamata dati generica post-login. operation tipicamente "go" (get), "so" (set), "gl" (get list). */
    public JsonNode call(String oid, String operation, Map<String, Object> data) throws ArcherException {
        try {
            ObjectNode payload = mapper.createObjectNode();
            payload.set("data", mapper.valueToTree(data == null ? Map.of() : data));
            payload.put("operation", operation);
            payload.put("oid", oid);

            String raw = signedPost(mapper.writeValueAsString(payload), false).trim();
            if (raw.isEmpty()) {
                return null;
            }
            return mapper.readTree(raw);
        } catch (ArcherException ae) {
            throw ae;
        } catch (Exception e) {
            throw new ArcherException("Chiamata a " + oid + " (" + operation + ") fallita", e);
        }
    }

    // ------------------------------------------------------------------ //
    // Alto livello
    // ------------------------------------------------------------------ //

    /** Effettua il login (handshake RSA+AES) e recupera cookie di sessione + token CSRF. */
    public void login(String password) throws ArcherException {
        try {
            fetchGdprParm();
            this.hash = ArcherCrypto.md5Hex(username + password);
            this.aesKey = ArcherCrypto.randomToken16();
            this.aesIv = ArcherCrypto.randomToken16();

            ObjectNode data = mapper.createObjectNode();
            data.put("UserName", base64(username));
            data.put("Passwd", base64(password));
            data.put("Action", "1");
            data.put("stack", "0,0,0,0,0,0");
            data.put("pstack", "0,0,0,0,0,0");

            ObjectNode payload = mapper.createObjectNode();
            payload.set("data", data);
            payload.put("operation", "cgi");
            payload.put("oid", "/cgi/login");

            String raw = signedPost(mapper.writeValueAsString(payload), true).trim();
            if (!raw.contains("ret=0")) {
                throw new ArcherException("Login fallito, risposta del router: " + raw, null);
            }

            fetchSessionToken();
        } catch (ArcherException ae) {
            throw ae;
        } catch (Exception e) {
            throw new ArcherException("Login fallito", e);
        }
    }

    /**
     * Il router non usa un vero header/cookie per il token CSRF: dopo il
     * login, la home page ("/"), se richiesta col cookie JSESSIONID valido,
     * contiene {@code <script>var token="...";</script>} generato lato
     * server. Va estratto da qui.
     */
    private void fetchSessionToken() throws ArcherException {
        HttpResponse<String> resp = get("/", Map.of());
        Matcher m = TOKEN_PATTERN.matcher(resp.body());
        if (!m.find()) {
            throw new ArcherException("Impossibile recuperare il token di sessione dalla home page", null);
        }
        this.token = m.group(1);
    }

    private static String base64(String s) {
        return java.util.Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * One page of the SMS inbox: the messages themselves ({@code entries}, an
     * array of {index, from, content, receivedTime, unread}) plus the page
     * summary returned by the router ({@code summary}: totalNumber,
     * unreadNumber, pageNumber, amountPerPage) — the latter is what lets a
     * caller compute how many pages the whole inbox spans.
     */
    public record InboxPage(JsonNode entries, JsonNode summary) {
    }

    /** Lists the SMS inbox (DEV2_LTE_SMS_RECVMSGBOX/RECVMSGENTRY objects). */
    public InboxPage inbox(int page) throws ArcherException {
        call("DEV2_LTE_SMS_RECVMSGBOX", "so",
                Map.of("PageNumber", String.valueOf(page), "stack", "0,0,0,0,0,0", "pstack", "0,0,0,0,0,0"));
        JsonNode summaryResp = call("DEV2_LTE_SMS_RECVMSGBOX", "go",
                Map.of("stack", "0,0,0,0,0,0", "pstack", "0,0,0,0,0,0"));
        JsonNode entriesResp = call("DEV2_LTE_SMS_RECVMSGENTRY", "gl",
                Map.of("stack", "0,0,0,0,0,0", "pstack", "0,0,0,0,0,0"));
        JsonNode entries = entriesResp == null ? mapper.createArrayNode() : entriesResp.path("data");
        JsonNode summary = summaryResp == null ? mapper.createObjectNode() : summaryResp.path("data");
        return new InboxPage(entries, summary);
    }

    /**
     * Invia un SMS (DEV2_LTE_SMS_SENDNEWMSG) e opzionalmente attende l'esito
     * facendo polling dello stato ("go") fino a un sendResult definitivo.
     * sendResult osservati: "3" = invio in corso, "1" = inviato con successo.
     */
    public JsonNode sendSms(String to, String text, boolean waitResult, Duration timeout) throws ArcherException {
        JsonNode resp = call("DEV2_LTE_SMS_SENDNEWMSG", "so", Map.of(
                "index", "1",
                "to", to,
                "textContent", text,
                "stack", "0,0,0,0,0,0",
                "pstack", "0,0,0,0,0,0"
        ));
        if (resp == null || !resp.path("success").asBoolean(false)) {
            throw new ArcherException("Invio SMS fallito: " + resp, null);
        }
        if (!waitResult) {
            return resp;
        }

        Instant deadline = Instant.now().plus(timeout);
        JsonNode last = null;
        while (Instant.now().isBefore(deadline)) {
            JsonNode status = call("DEV2_LTE_SMS_SENDNEWMSG", "go",
                    Map.of("stack", "0,0,0,0,0,0", "pstack", "0,0,0,0,0,0"));
            last = status == null ? null : status.path("data");
            if (last != null) {
                String sendResult = last.path("sendResult").asText(null);
                if (sendResult != null && !sendResult.equals("3") && !sendResult.equals("0")) {
                    return last;
                }
            }
            sleepQuiet(1000);
        }
        return last;
    }

    /**
     * Info SIM/rete/consumo dati. Gli OID richiedono stack "1,0,0,0,0,0"
     * (indice di istanza 1: gli oggetti SMS usano invece "0,0,0,0,0,0" -
     * senza questo dettaglio il router risponde errorcode 9003).
     */
    public Map<String, Object> simInfo() throws ArcherException {
        Map<String, Object> instance1 = Map.of("stack", "1,0,0,0,0,0", "pstack", "0,0,0,0,0,0");

        JsonNode usim = call("DEV2_CELL_INTF_USIM", "go", instance1);
        JsonNode netStatus = call("DEV2_LTE_NET_STATUS", "go", instance1);
        JsonNode linkCfg = call("DEV2_LTE_LINK_CFG", "go", instance1);
        JsonNode traffic = call("DEV2_XTP_LTE_INTF_CFG", "go", instance1);

        JsonNode u = data(usim);
        JsonNode n = data(netStatus);
        JsonNode l = data(linkCfg);
        JsonNode t = data(traffic);

        double totalBytes = t.path("totalStatistics").asDouble(0);
        double dailyBytes = t.path("dailyFlow").asDouble(0);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("iccid", textOrNull(u, "ICCID"));
        result.put("imsi", textOrNull(u, "IMSI"));
        result.put("msisdn", textOrNull(u, "MSISDN"));
        result.put("simStatus", textOrNull(u, "status"));
        result.put("signalStrength", textOrNull(n, "sigLevel"));
        result.put("smsCenter", textOrNull(l, "smsScAddress"));
        result.put("ipv4", textOrNull(l, "ipv4"));
        result.put("ipv6", textOrNull(l, "ipv6"));
        result.put("dns", List.of(textOrEmpty(l, "dns1v4"), textOrEmpty(l, "dns2v4")));
        result.put("connectedBands", textOrNull(l, "connectedBand"));
        result.put("roaming", "1".equals(textOrNull(l, "roamingStatus")));
        result.put("totalUsedGb", Math.round((totalBytes / Math.pow(1024, 3)) * 1000.0) / 1000.0);
        result.put("todayUsedMb", Math.round((dailyBytes / Math.pow(1024, 2)) * 10.0) / 10.0);
        result.put("dataLimitEnabled", "1".equals(textOrNull(t, "enableDataLimit")));
        result.put("dataLimitBytes", textOrNull(t, "dataLimit"));
        return result;
    }

    private static JsonNode data(JsonNode node) {
        return node == null ? com.fasterxml.jackson.databind.node.MissingNode.getInstance() : node.path("data");
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? null : v.asText();
    }

    private static String textOrEmpty(JsonNode node, String field) {
        String v = textOrNull(node, field);
        return v == null ? "" : v;
    }

    @Override
    public void close() {
        // Nessuna risorsa persistente da rilasciare: ogni richiesta usa un
        // HttpClient autonomo (vedi newHttpClient()). Il metodo esiste per
        // permettere try-with-resources nel Processor e per un futuro
        // logout esplicito (endpoint non ancora mappato, vedi PROTOCOL.md).
    }

    /** Eccezione applicativa per qualunque errore del protocollo/della chiamata HTTP. */
    public static class ArcherException extends Exception {
        public ArcherException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
