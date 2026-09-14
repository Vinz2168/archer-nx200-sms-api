# nifi-archer-router

Apache NiFi 2.x processor (`InvokeArcherRouter`) that reproduces, without
going through a browser, the management-panel protocol of TP-Link Archer
routers with a 4G/5G SIM in "GDPR encrypt" configuration (tested on the
Archer NX200): login, reading the SMS inbox, sending an SMS, reading
SIM/network/data-usage info.

For the full, verified protocol description (RSA+AES handshake,
session cookie/token, OIDs, known limitations) see **`../PROTOCOL.md`**.

## Build

Requires JDK 21+ and Maven. The `nifi-archer-router-processors` module
includes unit tests that verify the RSA/AES implementation **against a real
signature captured from the router** (not just generic test vectors).

```bash
mvn clean package
```

Produces `nifi-archer-router-nar/target/nifi-archer-router-nar-1.0.0.nar`.

If your NiFi instance is not the 2.11.0 used as the default target, update
`<nifi.version>` in the root `pom.xml` to match the exact installed version
(the API's major/minor must match, otherwise the NAR may fail to load).

The `bctls-jdk18on` (Bouncy Castle TLS) dependency is intentionally pinned
to `1.81.1`: version 1.86 has a real multi-release-JAR bug that throws
`NoSuchMethodError` at runtime on recent JVMs. See the comment on that
dependency in `nifi-archer-router-processors/pom.xml` before bumping it,
and re-verify with `ArcherClientLiveSmokeTool` (a manual tool under
`src/test/java`, not a JUnit test — see its Javadoc) against a real router.

## Installation

Copy the `.nar` into your NiFi installation's `lib/` (or `extensions/`,
depending on the version) directory and restart the node:

```bash
cp nifi-archer-router-nar/target/nifi-archer-router-nar-1.0.0.nar $NIFI_HOME/lib/
```

## Using the `InvokeArcherRouter` processor

| Property | Required | Notes |
|---|---|---|
| Router URL | yes | default `https://192.168.10.1` |
| Username | yes | default `user` (not `admin`: see PROTOCOL.md §2.2) |
| Password | yes | sensitive |
| Operation | yes | `INBOX`, `SEND_SMS`, `SIM_INFO` |
| Inbox page | only `INBOX` | default `0` |
| Recipient number | only `SEND_SMS` | supports Expression Language on FlowFile attributes |
| Message text | only `SEND_SMS` | if empty, uses the incoming FlowFile's content |
| Wait for send result | no | default `true`, polls for up to 20s |
| Trust all TLS certificates | yes | default `true` — required: the router uses a self-signed certificate with no subject/SAN |
| Connection timeout | yes | default `10 sec` |

**Relationships**: `success` (FlowFile with the JSON result), `original`
(the incoming FlowFile, if any, passed through unchanged), `failure` (the
incoming FlowFile, if any, on error).

The processor accepts an optional incoming FlowFile (useful to drive the
recipient number/text dynamically via attributes/content), or it can be used
as a scheduled source (e.g. every N minutes) for `INBOX`/`SIM_INFO`.

**Warning**: every execution forces a login, disconnecting any other active
session on the router (which only allows one at a time) — see
PROTOCOL.md §6.1.
