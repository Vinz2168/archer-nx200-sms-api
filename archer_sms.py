#!/usr/bin/env python3
"""
Client non ufficiale per il pannello di gestione dei router TP-Link Archer
(serie con SIM 4G/5G, firmware "GDPR encrypt" - es. Archer NX200) che
riproduce, senza usare il browser, il protocollo usato dalla WebUI per:
  - autenticarsi (handshake RSA + AES)
  - leggere gli SMS (posta in arrivo)
  - inviare un SMS

Protocollo (ricostruito facendo reverse engineering di js/tpEncrypt.js,
js/gdprProxy.js, js/encrypt.js e del flusso reale catturato dal browser):

1. GET/POST /cgi/getGDPRParm (non autenticato)
   -> risponde con JS eval-abile che definisce:
        nn   = modulo RSA (hex, 512 bit)
        ee   = esponente RSA (hex, di solito "010001" = 65537)
        seq  = intero, nonce di sessione (rimane fisso per tutta la sessione)

2. Si genera una chiave e un IV AES-128 "casuali" (nel client originale sono
   semplicemente cifre di timestamp+random, non serve altro che 16 byte).

3. hash = MD5(username + password)  (username di default: "user", vedi sotto)

4. Login:
   plaintext = JSON {"data":{"UserName": b64(username), "Passwd": b64(password),
                              "Action":"1", "stack":"0,0,0,0,0,0",
                              "pstack":"0,0,0,0,0,0"},
                      "operation":"cgi", "oid":"/cgi/login"}
   cipher = AES-128-CBC-PKCS7(plaintext, key, iv)   (poi base64)
   firma_input = "key=<key>&iv=<iv>&h=<hash>&s=<seq + len(cipher_base64)>"
   sign = RSA_raw_no_padding(firma_input, nn, ee)    (hex, a blocchi da 64 byte)
   body = "sign=<sign>\r\ndata=<cipher>\r\n"
   POST /cgi_gdpr?9  con questo body (Content-Type: text/plain)
   -> risposta = base64 AES che decifra in "$.ret=0;\x00" se OK

   NOTA IMPORTANTE: da qui in avanti la chiave/iv AES restano quelli
   scelti al passo 2 per TUTTA la sessione; `seq` NON cambia mai.

5. Ogni chiamata successiva (lettura/scrittura dati) usa lo stesso schema,
   ma la firma è solo "h=<hash>&s=<seq + len(cipher)>" (senza key/iv, che
   il server conosce già) e il "plaintext" è:
     {"data": {...}, "operation": "so"|"go"|"gl", "oid": "<OID_INTERNO>"}
   dove "so" = set (scrive un parametro), "go" = get (legge), "gl" = get list.

   OID rilevanti per gli SMS:
     DEV2_LTE_SMS_RECVMSGBOX    -> "so" {PageNumber}, poi "go" per i totali
     DEV2_LTE_SMS_RECVMSGENTRY  -> "gl" {stack:"0,0,0,0,0,0", pstack:"0,0,0,0,0,0"}
                                    ritorna un array di
                                    {index, from, content, receivedTime, unread, stack}
     DEV2_LTE_SMS_SENDNEWMSG    -> "so" {index, to, textContent} per inviare,
                                    poi "go" per leggere lo stato (sendResult)

6. Sessione: il login risponde con un cookie HttpOnly "JSESSIONID" (invisibile
   a document.cookie lato browser, va quindi ricavato dagli header HTTP grezzi
   e rimandato indietro ad ogni richiesta successiva). In più, la home page
   ("/"), se richiesta con quel cookie, contiene un
   <script>var token="...";</script> generato lato server: va estratto e
   rimandato nell'header "TokenID" di ogni chiamata /cgi_gdpr successiva al
   login, altrimenti il router risponde "406 Not Acceptable" a qualunque
   operazione so/go/gl (il login stesso invece funziona anche senza).
   Nessuno di questi due valori è mai citato nei file .js statici: sono
   entrambi impostati solo lato server per una sessione già autenticata,
   quindi individuabili solo osservando il traffico reale.

Uso:
    python3 archer_sms.py --password 'xxxxx' inbox
    python3 archer_sms.py --password 'xxxxx' send +393331234567 "ciao"

Testato contro: Archer NX200 (5G AX1800), firmware 1.2.0 3.0.0 v60e0.0.
"""
import argparse
import base64
import hashlib
import json
import random
import re
import sys
import time
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

RSA_BITS = 512
BLOCK_BYTES = RSA_BITS // 8      # 64 byte per blocco RSA senza padding
HEX_LEN = RSA_BITS // 4          # 128 caratteri hex per blocco


# --------------------------------------------------------------------------- #
# Crittografia
# --------------------------------------------------------------------------- #

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def rsa_raw_encrypt(plaintext: str, n_hex: str, e_hex: str) -> str:
    """Replica $.rsa.encrypt(text, nn, ee, 512, 0) di encrypt.js:
    nessun padding PKCS1, blocchi da 64 byte riempiti di zeri a destra,
    m^e mod n, output esadecimale zero-paddato a 128 caratteri per blocco."""
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    data = plaintext.encode("utf-8")
    out = []
    for i in range(0, len(data), BLOCK_BYTES):
        chunk = data[i:i + BLOCK_BYTES]
        chunk = chunk + b"\x00" * (BLOCK_BYTES - len(chunk))
        m = int.from_bytes(chunk, "big")
        c = pow(m, e, n)
        out.append(format(c, "0%dx" % HEX_LEN))
    return "".join(out)


def aes_encrypt(plaintext: str, key: str, iv: str) -> str:
    key_b = key.encode("utf-8")
    iv_b = iv.encode("utf-8")
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_b), modes.CBC(iv_b))
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(ct).decode("ascii")


def aes_decrypt(b64_ciphertext: str, key: str, iv: str) -> str:
    if not b64_ciphertext or not b64_ciphertext.strip():
        return ""
    key_b = key.encode("utf-8")
    iv_b = iv.encode("utf-8")
    ct = base64.b64decode(b64_ciphertext)
    cipher = Cipher(algorithms.AES(key_b), modes.CBC(iv_b))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode("utf-8", errors="replace").rstrip("\x00")


def gen_key_iv() -> tuple[str, str]:
    """Riproduce genKey() di tpEncrypt.js: 16 cifre da timestamp+random."""
    def token() -> str:
        s = str(int(time.time() * 1000)) + str(random.random() * 1_000_000_000)
        return s[:16]
    return token(), token()


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class ArcherError(RuntimeError):
    pass


class ArcherClient:
    def __init__(self, base_url: str, username: str = "user", verify_tls: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.verify_tls = verify_tls
        self.nn = self.ee = None
        self.seq = None
        self.aes_key = self.aes_iv = None
        self.hash = None
        self.jsessionid: Optional[str] = None
        self.token: str = "0"

    # -- basso livello ---------------------------------------------------- #

    def _post(self, path: str, data: bytes, extra_headers: Optional[dict] = None) -> requests.Response:
        # NOTA: il webserver del router non gestisce correttamente il
        # keep-alive quando il corpo contiene dei CRLF letterali (come nel
        # formato "sign=...\r\ndata=...\r\n" usato da /cgi_gdpr): riusare la
        # stessa connessione TCP per la richiesta successiva la fa rispondere
        # con "406 Not Acceptable" (o peggio). Ogni chiamata usa quindi una
        # connessione nuova (niente requests.Session persistente) e la chiude
        # subito dopo.
        #
        # Il router imposta comunque un cookie di sessione HttpOnly
        # (JSESSIONID) al login: essendo HttpOnly non è visibile a
        # document.cookie lato browser (per questo sfugge leggendo solo il
        # JS), ma è necessario rimandarlo indietro ad ogni chiamata
        # successiva, altrimenti il backend rifiuta/crasha la richiesta.
        headers = {"User-Agent": DEFAULT_UA, "Referer": self.base_url + "/", "Connection": "close",
                   "TokenID": self.token}
        if self.jsessionid:
            headers["Cookie"] = f"JSESSIONID={self.jsessionid}"
        if extra_headers:
            headers.update(extra_headers)
        last_exc = None
        for attempt in range(4):
            try:
                with requests.Session() as s:
                    r = s.post(f"{self.base_url}{path}", data=data, headers=headers, verify=self.verify_tls,
                               timeout=10)
                if "JSESSIONID" in r.cookies:
                    self.jsessionid = r.cookies["JSESSIONID"]
                return r
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                time.sleep(0.3 * (attempt + 1))
        raise last_exc

    def _get_gdpr_parm(self):
        r = self._post("/cgi/getGDPRParm", data=b"")
        r.raise_for_status()
        text = r.text
        vals = {}
        for line in text.splitlines():
            line = line.strip().rstrip(";")
            if line.startswith("var ") and "=" in line:
                k, v = line[4:].split("=", 1)
                vals[k.strip()] = v.strip().strip('"')
        self.nn = vals["nn"]
        self.ee = vals["ee"]
        self.seq = int(vals["seq"])

    def _signed_post(self, plaintext_json: str, is_login: bool) -> str:
        """Cifra plaintext_json, firma con RSA, POSTa su /cgi_gdpr?9,
        ritorna il plaintext decifrato della risposta."""
        cipher_b64 = aes_encrypt(plaintext_json, self.aes_key, self.aes_iv)
        s_val = self.seq + len(cipher_b64)
        if is_login:
            sign_input = f"key={self.aes_key}&iv={self.aes_iv}&h={self.hash}&s={s_val}"
        else:
            sign_input = f"h={self.hash}&s={s_val}"
        sign = rsa_raw_encrypt(sign_input, self.nn, self.ee)
        body = f"sign={sign}\r\ndata={cipher_b64}\r\n"
        r = self._post(
            "/cgi_gdpr?9",
            data=body.encode("utf-8"),
            extra_headers={"Content-Type": "text/plain"},
        )
        r.raise_for_status()
        return aes_decrypt(r.text, self.aes_key, self.aes_iv)

    def call(self, oid: str, operation: str, data: Optional[dict] = None) -> Any:
        """Chiamata generica post-login: operation in {"go","so","gl","ao","do","op"}."""
        payload = {
            "data": data or {},
            "operation": operation,
            "oid": oid,
        }
        raw = self._signed_post(json.dumps(payload), is_login=False)
        raw = raw.strip()
        if not raw:
            return None
        return json.loads(raw)

    # -- alto livello ------------------------------------------------------ #

    def login(self, password: str):
        self._get_gdpr_parm()
        self.hash = md5_hex(self.username + password)
        self.aes_key, self.aes_iv = gen_key_iv()

        payload = {
            "data": {
                "UserName": base64.b64encode(self.username.encode()).decode(),
                "Passwd": base64.b64encode(password.encode()).decode(),
                "Action": "1",
                "stack": "0,0,0,0,0,0",
                "pstack": "0,0,0,0,0,0",
            },
            "operation": "cgi",
            "oid": "/cgi/login",
        }
        raw = self._signed_post(json.dumps(payload), is_login=True)
        raw = raw.strip().rstrip("\x00;")
        # risposta attesa: "$.ret=0" (successo) oppure "$.ret=<codice errore>"
        if "ret=0" not in raw:
            raise ArcherError(f"Login fallito, risposta del router: {raw!r}")

        # Il router NON usa un vero header/cookie per il CSRF-token: dopo il
        # login, la home page ("/") viene servita con un
        # <script>var token="...";</script> incorporato lato server (visibile
        # solo con un cookie di sessione valido). Questo valore va rimandato
        # indietro nell'header "TokenID" di ogni chiamata successiva, oppure
        # il router risponde "406 Not Acceptable" a qualunque operazione
        # so/go/gl (il login stesso invece funziona anche senza).
        headers = {"User-Agent": DEFAULT_UA, "Referer": self.base_url + "/", "Connection": "close",
                   "Cookie": f"JSESSIONID={self.jsessionid}" if self.jsessionid else ""}
        with requests.Session() as s:
            r = s.get(self.base_url + "/", headers=headers, verify=self.verify_tls, timeout=10)
        m = re.search(r'var\s+token\s*=\s*"([0-9a-fA-F]+)"', r.text)
        if not m:
            raise ArcherError("Impossibile recuperare il token di sessione dalla home page")
        self.token = m.group(1)

    def sim_info(self) -> dict:
        """Info SIM/rete/consumo dati. OID scoperti dal traffico reale (stack
        "1,0,0,0,0,0": indice di istanza 1, non "0,0,0,0,0,0" come per gli
        oggetti SMS - senza questo l'oid risponde errorcode 9003)."""
        usim = self.call("DEV2_CELL_INTF_USIM", "go", {"stack": "1,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
        net_status = self.call("DEV2_LTE_NET_STATUS", "go", {"stack": "1,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
        link_cfg = self.call("DEV2_LTE_LINK_CFG", "go", {"stack": "1,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
        traffic = self.call("DEV2_XTP_LTE_INTF_CFG", "go", {"stack": "1,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})

        u = usim.get("data", {}) if usim else {}
        n = net_status.get("data", {}) if net_status else {}
        l = link_cfg.get("data", {}) if link_cfg else {}
        t = traffic.get("data", {}) if traffic else {}

        total_bytes = float(t.get("totalStatistics", 0) or 0)
        daily_bytes = float(t.get("dailyFlow", 0) or 0)

        return {
            "iccid": u.get("ICCID"),
            "imsi": u.get("IMSI"),
            "msisdn": u.get("MSISDN") or None,
            "sim_status": u.get("status"),
            "signal_strength": n.get("sigLevel"),
            "sms_center": l.get("smsScAddress"),
            "ipv4": l.get("ipv4"),
            "ipv6": l.get("ipv6"),
            "dns": [l.get("dns1v4"), l.get("dns2v4")],
            "connected_bands": l.get("connectedBand"),
            "roaming": l.get("roamingStatus") == "1",
            "total_used_gb": round(total_bytes / (1024 ** 3), 3),
            "today_used_mb": round(daily_bytes / (1024 ** 2), 1),
            "data_limit_enabled": t.get("enableDataLimit") == "1",
            "data_limit_bytes": t.get("dataLimit"),
        }

    def inbox(self, page: int = 0) -> list[dict]:
        self.call("DEV2_LTE_SMS_RECVMSGBOX", "so",
                  {"PageNumber": str(page), "stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
        summary = self.call("DEV2_LTE_SMS_RECVMSGBOX", "go",
                             {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
        entries = self.call("DEV2_LTE_SMS_RECVMSGENTRY", "gl",
                             {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
        result = entries.get("data", []) if entries else []
        for e in result:
            e["_summary"] = summary.get("data") if summary else None
        return result

    def send_sms(self, to: str, text: str, wait_result: bool = True, timeout: float = 20.0) -> dict:
        resp = self.call("DEV2_LTE_SMS_SENDNEWMSG", "so", {
            "index": "1",
            "to": to,
            "textContent": text,
            "stack": "0,0,0,0,0,0",
            "pstack": "0,0,0,0,0,0",
        })
        if not resp or not resp.get("success"):
            raise ArcherError(f"Invio SMS fallito: {resp}")

        if not wait_result:
            return {"success": True}

        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            status = self.call("DEV2_LTE_SMS_SENDNEWMSG", "go",
                                {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"})
            last = status.get("data") if status else None
            # sendResult osservati: "3" = invio in corso, "1" = inviato con successo
            if last and last.get("sendResult") not in (None, "3", "0"):
                return last
            time.sleep(1)
        return last or {"success": True, "note": "timeout in attesa dello stato"}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="https://192.168.10.1", help="URL base del router")
    p.add_argument("--user", default="user", help='Username per il login (default: "user")')
    p.add_argument("--password", required=True, help="Password del pannello")
    p.add_argument("--release-session", action="store_true",
                    help="TODO: rilascia la sessione a fine esecuzione invece di lasciarla aperta "
                         "(serve altrimenti, se poi ti logghi dalla GUI, a confermare a mano il "
                         "\"forzare il logout dell'altro dispositivo?\". Endpoint di logout non "
                         "ancora mappato: al momento questo flag non fa nulla, da decidere dopo "
                         "se implementarlo o lasciare che sia il prossimo login a prendere il posto).")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("inbox", help="Elenca gli SMS in posta in arrivo")
    sub.add_parser("siminfo", help="Info SIM: ICCID/IMSI, segnale, IP, consumo dati")

    p_send = sub.add_parser("send", help="Invia un SMS")
    p_send.add_argument("to", help="Numero destinatario, es. +393331234567")
    p_send.add_argument("text", help="Testo del messaggio")
    p_send.add_argument("--no-wait", action="store_true", help="Non attendere l'esito dell'invio")

    args = p.parse_args()

    client = ArcherClient(args.url, username=args.user)
    client.login(args.password)

    if args.cmd == "inbox":
        for m in client.inbox():
            print(f"[{m.get('index')}] da {m.get('from')!r} il {m.get('receivedTime')} "
                  f"(non letto: {m.get('unread')})\n    {m.get('content')}\n")
    elif args.cmd == "send":
        result = client.send_sms(args.to, args.text, wait_result=not args.no_wait)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.cmd == "siminfo":
        print(json.dumps(client.sim_info(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except ArcherError as e:
        print(f"Errore: {e}", file=sys.stderr)
        sys.exit(1)
