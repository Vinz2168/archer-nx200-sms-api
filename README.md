# archer-nx200-sms-api

Reverse-engineered (not official documentation) protocol used by the WebUI
of TP-Link Archer routers with a 4G/5G SIM, "GDPR encrypt" firmware (tested
on an **Archer NX200**, 5G AX1800), reimplemented in multiple languages/
targets to read/send SMS and read SIM/network/data-usage info without going
through the browser.

The protocol (RSA 512-bit + AES-128-CBC handshake, JSESSIONID/TokenID
session handling, list of verified application OIDs, known limitations) is
documented in full in **[`PROTOCOL.md`](PROTOCOL.md)** (in Italian): it's
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
