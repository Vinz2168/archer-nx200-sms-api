# archer-nx200-sms-api

Reverse-engineered (not official documentation) protocol used by the WebUI
of TP-Link Archer routers with a 4G/5G SIM, "GDPR encrypt" firmware (tested
on an **Archer NX200**, 5G AX1800), reimplemented in multiple languages/
targets to read/send SMS and read SIM/network/data-usage info without going
through the browser.

The protocol (RSA 512-bit + AES-128-CBC handshake, JSESSIONID/TokenID
session handling, list of verified application OIDs, known limitations) is
documented in full in **[`PROTOCOL.md`](PROTOCOL.md)**: it's
the shared reference for every implementation below, there's no
per-language copy of it.

## What's in the repo

| | Language | What it does |
|---|---|---|
| [`archer_sms.py`](archer_sms.py) | Python | Reference CLI client: the first implementation of the protocol, used to verify it. |
| [`nifi-archer-router/`](nifi-archer-router/) | Java | Apache NiFi 2.x processor (`InvokeArcherRouter`) to integrate the panel into a NiFi pipeline. |
| [`mcp-archer-router/`](mcp-archer-router/) | Rust | [MCP](https://modelcontextprotocol.io) server (stdio) and/or REST API, to use the panel from an agent/LLM or over HTTP. Self-contained native binary. |

All three implementations cover the same operations (login, reading the SMS
inbox, sending an SMS, SIM/network/data-usage info) with the same behavior
towards the router: default username `"user"` (not `"admin"`), a
self-signed TLS certificate that must be explicitly trusted, and the same
practical rule about the session — **the router only accepts one
administrative session at a time**: a new login (from a script or another
client, including the browser) silently overrides the previous one, with
no warning. Keeping the GUI open while an automated client is running
causes intermittent failures (see `PROTOCOL.md` §6.1). The NiFi processor
and the Rust server both handle this with an automatic retry on expired
session (except for sending an SMS, to avoid a duplicate send if the
session drops mid-poll while waiting for the result); the Python client is
meant for a single one-off command and doesn't do this.

Each of the three directories has its own README with build/usage
instructions specific to that language/target.

## Running the server

The Rust binary in [`mcp-archer-router/`](mcp-archer-router/) is the
long-running "server" option (MCP over stdio and/or a REST API over HTTP);
`archer_sms.py` and the NiFi processor are one-off/pipeline clients instead.
Full detail (session handling, MCP client config, cross-compiling) is in
[`mcp-archer-router/README.md`](mcp-archer-router/README.md) — this is the
quick version to get it running.

### 1. Get a binary

Either download the archive for your platform from the
[Releases page](https://github.com/Vinz2168/archer-nx200-sms-api/releases)
(macOS arm64/x86_64, Linux x86_64 static, Windows x86_64) and extract
`mcp-archer-router`, or build it yourself:

```
cd mcp-archer-router
cargo build --release
# binary at target/release/mcp-archer-router
```

### 2. Start it

Everything is configured via environment variables — there are no CLI
flags. Minimal example running only the REST API:

```
ARCHER_PASSWORD="the-router-admin-password" \
ARCHER_REST_ENABLED=true \
./mcp-archer-router
```

This starts listening on `127.0.0.1:8787` (default) and lazily logs into
`https://192.168.10.1` (default) the first time an endpoint is called.
Check it's up with:

```
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/sim/info
```

### 3. Parameters (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `ARCHER_ROUTER_URL` | `https://192.168.10.1` | Base URL of the router's admin panel. |
| `ARCHER_USERNAME` | `user` | Login username. On models like the NX200 (no username field in the GUI) it's `"user"`, not `"admin"`. |
| `ARCHER_PASSWORD` | *(required)* | Login password of the admin panel. Process refuses to start without it. |
| `ARCHER_TRUST_ALL_CERTS` | `true` | The panel serves a self-signed TLS certificate with no subject/SAN (`PROTOCOL.md` §6.3); leave `true` unless you've installed a valid certificate. |
| `ARCHER_MCP_ENABLED` | `true` | Enables the MCP server on stdio. |
| `ARCHER_REST_ENABLED` | `false` | Enables the REST API over HTTP (see endpoints below). |
| `ARCHER_REST_BIND` | `127.0.0.1:8787` | `host:port` the REST API listens on, only used if `ARCHER_REST_ENABLED=true`. |

At least one of `ARCHER_MCP_ENABLED`/`ARCHER_REST_ENABLED` must stay
`true`, or the process logs an error and exits non-zero. Both transports
share the same cached login/session (the router only allows one
administrative session at a time — see §6.1 in `PROTOCOL.md`).

**The REST API has no authentication of its own.** `ARCHER_REST_BIND`
defaults to `127.0.0.1` on purpose — only change it to bind on a wider
interface (e.g. `0.0.0.0:8787` on a homeserver/LAN) if that network is
already trusted, since anyone who can reach the port can read SMS and send
them through your router.

### REST endpoints

| Method & path | Description |
|---|---|
| `GET /health` | Static health check, doesn't touch the router. |
| `GET /sim/info` | ICCID/IMSI, signal, assigned IP, total/today data usage. |
| `GET /sms/inbox?page=0` | Lists received SMS. `page` is optional, 0-based, default `0`. |
| `POST /sms/send` | Sends an SMS. Body `{"to": "...", "text": "...", "wait_result": true}`; `wait_result` (optional, default `true`) waits up to 20s for the send outcome. |

Any error talking to the router comes back as `502 Bad Gateway` with body
`{"error": "..."}`; a malformed request (invalid JSON, missing field) is
rejected earlier with `400`/`422`.

### Running it in the background (e.g. on a homeserver)

There's no daemon/service-manager integration built in — run it under
whatever supervises long-running processes on your system, for example a
systemd unit or a `screen`/`tmux` session, passing the environment
variables above. A pre-built static Linux binary
(`x86_64-unknown-linux-musl`) is what you want for a typical homeserver: no
glibc version constraints.

## Status

Verified end-to-end against a real Archer NX200, with valid credentials:
login, `sim_info`, `sms_inbox` and `sms_send` all work across every
implementation. Not yet explored: the router's firmware (to understand how
users/permissions are handled beyond `user`/`admin`) — see `PROTOCOL.md`
§8 for the known gaps.

## Responsible use

This repository is the result of reverse-engineering the WebUI of one's
own router, for interoperability and personal automation purposes (e.g.
feeding a 4G/5G SIM's SMS into a home pipeline). It is not official TP-Link
software and comes with no warranty: only use it against routers you own
or are authorized to access, with legitimate credentials.
