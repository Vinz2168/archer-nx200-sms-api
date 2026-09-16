# mcp-archer-router

[MCP](https://modelcontextprotocol.io) server (stdio) **and/or** REST API
(JSON over HTTP) for the management panel of TP-Link Archer routers with a
4G/5G SIM (firmware "GDPR encrypt", tested on the **Archer NX200**). Same
functionality as `archer_sms.py` and the NiFi processor in
`nifi-archer-router/`: reading the SMS inbox, sending SMS, SIM/network/data-
usage info — reproduced in Rust with no external dependencies beyond
system libraries.

See `PROTOCOL.md` in the repository root for the full protocol
description.

## Transport: MCP, REST, or both

The two transports are turned on/off independently (`ARCHER_MCP_ENABLED` /
`ARCHER_REST_ENABLED`, see Configuration) and, when both are active, they
share **the same session** towards the router (same cached login): the
router only accepts one at a time, so it wouldn't make sense to have two
independent logins. Every error talking to the router, on either
transport, is logged (ERROR level) to stderr before being translated into
the MCP client response or the REST JSON body.

### Exposed tools / endpoints

| MCP tool | REST endpoint | Description |
|---|---|---|
| `sms_inbox` | `GET /sms/inbox?page=0` | Lists received SMS. `page` optional, 0-based, default 0. |
| `sms_send` | `POST /sms/send` (body `{"to","text","wait_result"?}`) | Sends an SMS. `wait_result` default `true`: waits up to 20s for the outcome. |
| `sim_info` | `GET /sim/info` | ICCID/IMSI, signal, assigned IP, total/today data usage. |
| — | `GET /health` | Static health check (doesn't touch the router), for readiness probes. |

The REST API has **no authentication**: it's meant to be exposed only on
`localhost` or on an already-trusted network (default
`ARCHER_REST_BIND=127.0.0.1:...` — only change it if you know what exposing
it elsewhere implies). Any error towards the router always becomes
`502 Bad Gateway` with body `{"error": "..."}`; a malformed request
(invalid JSON, missing field) is already intercepted by `axum` before
reaching the router, with `400`/`422`.

## Session

**Lazy** login: the first call to a tool authenticates and caches the
session cookie + CSRF token; subsequent calls reuse the session. If the
router reports that the session is no longer valid (typically because
someone else logged in meanwhile, e.g. from the browser GUI — the router
accepts only one administrative session at a time, see PROTOCOL.md §6.1),
the server re-authenticates and automatically retries the operation
**once**, except for `sms_send`: if the session expires *while* waiting for
the outcome (i.e. after the SMS has already been queued successfully), the
operation is not repeated to avoid a duplicate send — the tool still
returns `success: true` with a note that the final outcome wasn't
confirmed.

All calls share a single session behind a lock: there's no real
concurrency towards the router, which wouldn't support it anyway (only one
session at a time).

## Configuration

Environment variables:

| Variable | Default | Notes |
|---|---|---|
| `ARCHER_ROUTER_URL` | `https://192.168.10.1` | Base URL of the panel. |
| `ARCHER_USERNAME` | `user` | On models like the NX200, with no username field in the GUI, it's `"user"`, not `"admin"`. |
| `ARCHER_PASSWORD` | *(required)* | Password of the panel. |
| `ARCHER_TRUST_ALL_CERTS` | `true` | The panel uses a self-signed TLS certificate with no subject/SAN (see PROTOCOL.md §6.3): leave `true` unless you've installed a valid certificate. |
| `ARCHER_MCP_ENABLED` | `true` | MCP server over stdio. |
| `ARCHER_REST_ENABLED` | `false` | REST JSON API over HTTP (see above). |
| `ARCHER_REST_BIND` | `127.0.0.1:8787` | REST listen address:port, only used if `ARCHER_REST_ENABLED=true`. |

At least one of `ARCHER_MCP_ENABLED` and `ARCHER_REST_ENABLED` must stay
`true`, otherwise the process refuses to start (error log + non-zero
exit).

## Precompiled binaries

Every `vX.Y.Z` tag (see [Releases](https://github.com/Vinz2168/archer-nx200-sms-api/releases))
triggers a GitHub Action (`.github/workflows/release.yml`, at the repo
root) that natively compiles and publishes binaries for:

- macOS Apple Silicon (`aarch64-apple-darwin`)
- macOS Intel (`x86_64-apple-darwin`)
- Linux x86_64, statically linked (`x86_64-unknown-linux-musl`)
- Windows x86_64 (`x86_64-pc-windows-msvc`)

Each archive (`.tar.gz` for macOS/Linux, `.zip` for Windows) contains the
binary, this README and `PROTOCOL.md`. To build from source instead, see
below.

## Build

```
cargo build --release
```

Produces a self-contained native binary at
`target/release/mcp-archer-router` (TLS via `rustls`, not
OpenSSL/native-tls: on macOS the only dynamic dependencies are system
libraries — verifiable with `otool -L`, on Linux with `ldd`).

### Cross-compiling for Linux x86_64 (e.g. for a homeserver)

From macOS, with [`cross`](https://github.com/cross-rs/cross) (requires
Docker):

```
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target x86_64-unknown-linux-musl
```

Target `musl`, not `gnu`: produces a **statically linked** binary (`ldd`
shows only its own musl loader, no external libraries) — runs on any
Linux x86_64 distro with no glibc version constraints. The resulting
binary is at `target/x86_64-unknown-linux-musl/release/mcp-archer-router`;
a `strip` (e.g. `docker run --rm --platform linux/amd64 -v
"$PWD/...:/out" alpine sh -c "apk add -q binutils && strip
/out/mcp-archer-router"`) shrinks it by about a quarter. Verified (this
way, cross-compiled from macOS arm64) both with `file`/`ldd` and with an
actual run inside a `--platform linux/amd64` container.

## Configuration in an MCP client

Example for a client that reads an `mcp.json`/`claude_desktop_config.json`
file:

```json
{
  "mcpServers": {
    "archer-router": {
      "command": "/path/to/target/release/mcp-archer-router",
      "env": {
        "ARCHER_ROUTER_URL": "https://192.168.10.1",
        "ARCHER_USERNAME": "user",
        "ARCHER_PASSWORD": "***"
      }
    }
  }
}
```

## Status

Compiles, passes the cryptographic tests (`cargo test`: MD5, AES-128-CBC,
raw RSA signing verified against known vectors/a test key) and is
**verified end-to-end against a real Archer NX200**, with correct
credentials: RSA/AES-128-CBC handshake, session (JSESSIONID + TokenID),
login, `sim_info` and `sms_inbox` return real data from the router, on
both transports (MCP via JSON-RPC over stdio, REST over HTTP),
individually and together, including `sms_send` (dedicated example
`send_test_sms.rs`, separate from `live_check.rs` which stays read-only):
SMS sent successfully, `sendResult: "1"` confirmed by the router. Not yet
exercised: automatic retry on an expired/stolen session (would require a
second concurrent login, e.g. from the GUI, during a test).
