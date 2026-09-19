# Two independently configured `btx-hcpd` instances (loopback REGTEST lab)

Isolated **loopback** only. Not mainnet. Not a wallet proxy. Not production
`btxd`. This kit does not start mining, open a monetary wallet, or replace
the live CUDA GPU attestor (`btxd.real`). `automatic_spend_atoms` stays **0**.

Helper: [`run-two-instances.sh`](run-two-instances.sh) (same topology).

## Instances

Two processes, independently configured (`-datadir`, `-instance`, bind, preset).
They do not share catalogue, ledger, or OAuth state.

| Process | Bind | Flags | Profiles |
|---|---|---|---|
| A walletless | `127.0.0.1:18780` | `-walletless -instance=hcp-a` | **DISCOVERY**, **HANDOFF** (`custody_modes`: `DISCOVERY_ONLY`) |
| B finance lab (optional) | `127.0.0.1:18781` | `-finance=1 -instance=hcp-b` | + CUSTODY, **FUNDING**, FLEET (`custody_modes`: `CUSTODIAL`) |
| Local client | no HTTP | `btx-hosted walletless` | walletless connector; not a wallet |

Bind must stay `127.0.0.1` (or `localhost`). `btx-hcpd` refuses any other host.
Do not pass `-bind=0.0.0.0`, a LAN address, or a public interface.

`btx-hcpd` does **not** load `config.example.yaml`. Pass flags. `-walletless`
and `-finance=1` select the preset; `-datadir=` and `-instance=` overlay after.
The daemon then forces `automatic_spend_atoms=0`.

Instance B is the optional FUNDING lab. Skip `-finance=1` (or start a second
`-walletless` on `:18781`) if you only want two DISCOVERY/HANDOFF origins.
Unauthenticated finance fail-closes. Loopback `GET /lab/pkce`,
`/lab/authorize`, `/lab/token`, `/lab/dpop` are **OAUTH_LAB** (REGTEST,
loopback only) and are **not** a live CEX IdP.

## 0. Binaries (do not ninja from this document)

Prefer an existing tree. Never compile from this demo. Never replace
production `btxd.real`.

```bash
# 1) cmake BUILDDIR, if set and populated
# 2) else the 0.34.8-regtest prefix, if installed
if [[ -n "${BUILDDIR:-}" && -x "$BUILDDIR/bin/btx-hcpd" ]]; then
  BIN="$BUILDDIR/bin"
elif [[ -x "$HOME/.local/opt/btx-0.34.8-regtest/bin/btx-hcpd" ]]; then
  BIN="$HOME/.local/opt/btx-0.34.8-regtest/bin"
else
  echo "no btx-hcpd (set BUILDDIR or install the 0.34.8-regtest prefix)" >&2
  return 1
fi
test -x "$BIN/btx-hcpd" && test -x "$BIN/btx-hosted"
```

Or:

```bash
bash contrib/modelnet/hcp-gateway/run-two-instances.sh
```

Preconditions: isolated **REGTEST / loopback**. Do not point these processes
at production `btxd`, CUDA goldens, or a live attestor. Do not
`systemctl --user stop` production. Terminate only the PIDs this lab started
(SIGTERM, not SIGKILL of production).

## 1. Start two independently configured gateways

```bash
DATAA=$(mktemp -d /tmp/hcp-a.XXXXXX)
DATAB=$(mktemp -d /tmp/hcp-b.XXXXXX)

"$BIN/btx-hcpd" -walletless -datadir="$DATAA" -instance=hcp-a -bind=127.0.0.1:18780 &
PID_A=$!
"$BIN/btx-hcpd" -finance=1 -datadir="$DATAB" -instance=hcp-b -bind=127.0.0.1:18781 &
PID_B=$!
```

Wait until each answers `GET /profile` (HTTP 200, `object_type` =
`ProviderProfile`). Walletless `supported_profiles` is DISCOVERY+HANDOFF.
The optional finance lab also advertises FUNDING/CUSTODY/FLEET.

```bash
curl -sS http://127.0.0.1:18780/profile
curl -sS http://127.0.0.1:18781/profile
```

Expect HTTP 200 and a signed envelope. Compare `supported_profiles` /
`custody_modes` between the two origins — they must differ when B is
`-finance=1`. Catalogue search may return **empty** `hits` with
`incomplete: true`; that is valid (no invented capacity).

Optional health check (`automatic_spend_atoms` is 0 on both):

```bash
curl -sS http://127.0.0.1:18780/health
curl -sS http://127.0.0.1:18781/health
```

## 2. Local client — `btx-hosted walletless`

One-shot connector. It is not an HTTP server and not a wallet:

```bash
"$BIN/btx-hosted" walletless
```

Expect JSON with `"walletless": true`, `"start_wallet": false`,
`"start_mining": false`, `"automatic_spend_atoms": 0`,
`"expose_runtime_to_gateway": false`. Pairing keys stay on this client;
the browser portal must not hold them.

## 3. Curl — `/profile`

Public read. No `Authorization` header.

```bash
curl -sS -D - -o /tmp/hcp-profile-a.json http://127.0.0.1:18780/profile
curl -sS -D - -o /tmp/hcp-profile-b.json http://127.0.0.1:18781/profile
```

Pass: both HTTP 200. Fail: any non-loopback bind, or a body that looks like
wallet RPC.

## 4. Curl — catalogue search (DISCOVERY)

`POST /capabilities/search` is a typed DISCOVERY operation. Empty body is
accepted; `{}` is canonical BTX-PJSON1. Do **not** send an Authorization
header on this public demo (a stray Bearer without DPoP fail-closes).

```bash
curl -sS -D - -o /tmp/hcp-search.json \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:18780/capabilities/search
```

Pass: HTTP 200, JSON with `hits` (array), `incomplete` (true in this lab),
`query_budget`. Sponsored / rank fields, if present, are **catalogue
annotations**, not protocol facts. Repeat against `:18781` — independent
datadir, independent catalogue.

Natural-language `q` stays data (`{"q":"document.classification"}` with
sorted keys, no spaces). It must not become `createwallet` or SQL.

## 5. Curl — `/rpc` is 404 (typed operations only)

Generic JSON-RPC passthrough is disabled (`GENERIC_RPC_DISABLED`).

```bash
curl -sS -D - -o /tmp/hcp-rpc.json -X POST \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:18780/rpc

curl -sS -D - -o /tmp/hcp-rpc-get.json http://127.0.0.1:18781/rpc
```

Pass: HTTP **404**, body contains `"code":"GENERIC_RPC_DISABLED"`. Same on
both instances. There is no wallet RPC, no `sendrawtransaction`, no
`createwallet` here.

## 6. Curl — unauthenticated finance fail-closed

On the **optional finance lab** (`:18781`, `-finance=1`) the FUNDING
profile is on, so the finance gate opens and **auth** fail-closes:

```bash
curl -sS -D - -o /tmp/hcp-fin-unauth.json -X POST \
  http://127.0.0.1:18781/finance/quotes

curl -sS -D - -o /tmp/hcp-intent-unauth.json -X POST \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:18781/finance/intents
```

Pass: HTTP **401**, `"code":"UNAUTHENTICATED"`. No quote, no hold, no spend.
`automatic_spend_atoms` stays 0. This is **not** live CEX IdP, live HSM, or
a native broadcast.

On the **walletless** instance the funding profile is off, so the same
paths fail closed even before a token is considered:

```bash
curl -sS -D - -o /tmp/hcp-fin-off.json -X POST \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:18780/finance/quotes
```

Pass: HTTP **403**, `"code":"FUNDING_DISABLED"`.

HTTP **202** (not exercised by these unauth curls) would mean UNKNOWN, not
settlement. Clients must not auto-submit on 202 or timeout; reuse the same
`client_operation_id`.

## 7. What this lab does not prove

Honest **NOT_RUN** (do not report as PASS):

- Live CEX identity provider (in-process `OAUTH_LAB` only)
- Live custody HSM (`-finance=1` uses `BTX_NATIVE_TEMPLATES` lab)
- Live CUDA DMA / ExactReplay (do not starve or replace the GPU attestor)
- Production `btxd.real` replacement — **forbidden**

Operator rollout order: DISCOVERY, then HANDOFF, then FUNDING. See
[`doc/hosted/HCP_OPERATOR_NOTES.md`](../../../doc/hosted/HCP_OPERATOR_NOTES.md).

## 8. Reference portal

`contrib/modelnet/hcp-portal/` — catalogue/search, terms/quote, approvals,
treasury (no auto-submit on 202), devices (outbound pairing, no token in
URI), progress, export. Ranking copy is labelled as catalogue annotation.
The browser cannot possess custody keys.

## 9. Cleanup

SIGTERM the two lab `btx-hcpd` PIDs you started. Do **not** SIGKILL
production `btxd`. Do not `killall btx-hcpd` (that could hit another lab).
Delete the temp datadirs. `/tmp` is tmpfs — do not leave them.

```bash
kill -TERM "$PID_A" "$PID_B"
rm -rf "$DATAA" "$DATAB"
```

## 10. Cognitive Reserve v1.1 — two independently configured instances

Additive notes for the **same** loopback PIDs started in §1. Cognitive
Reserve is a **negotiated HCP/1 extension**, not a fifth plane and not a
second `btx-hcpd` binary. The original **34** typed ops stay on both
origins (`/profile` 200, `/rpc` 404 `GENERIC_RPC_DISABLED`).
`automatic_spend_atoms` stays **0**. Do not ninja. Do not replace
production `btxd.real`. `CLIENT_VERSION_IS_RELEASE` remains **false**.

In this kit the walletless preset leaves the extension **off**. The
optional `-finance=1` preset turns `cr11_enabled` on **in-process**. That
is lab negotiation, not live CEX IdP, live HSM, or a shipping claim. The
two datadirs still do not share catalogue, ledger, OAuth, or reserve state.

### 10.1 Health — extension advertised independently

```bash
curl -sS http://127.0.0.1:18780/health
curl -sS http://127.0.0.1:18781/health
```

Pass: both HTTP 200, both `"automatic_spend_atoms": 0`. Walletless A has
`"cognitive_reserve": false` (and `"walletless": true`). Optional finance
lab B has `"cognitive_reserve": true` (and `"finance": true`) when started
with `-finance=1`. Fail: a third process claimed as a “reserve plane”, or
any non-zero automatic spend.

### 10.2 Walletless A — extension routes fail closed

`GET /extensions/cognitive-reserve` (and every `/reserve/*`, `/capital/*`
path) is **not** a public-read catalogue. With the extension off, the
walletless origin fail-closes **before** a token is considered:

```bash
curl -sS -D - -o /tmp/cr11-ext-a.json \
  http://127.0.0.1:18780/extensions/cognitive-reserve

curl -sS -D - -o /tmp/cr11-port-a.json -X POST \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:18780/reserve/portfolios
```

Pass: HTTP **403**, `"code":"PROFILE_UNSUPPORTED"`. Do **not** retry the
same body against `/finance/intents` as a silent substitute.

### 10.3 Finance lab B — unauthenticated extension fail-closed

On `-finance=1` the extension is on, so **auth** fail-closes:

```bash
curl -sS -D - -o /tmp/cr11-ext-b-unauth.json \
  http://127.0.0.1:18781/extensions/cognitive-reserve

curl -sS -D - -o /tmp/cr11-port-b-unauth.json -X POST \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://127.0.0.1:18781/reserve/portfolios
```

Pass: HTTP **401**, `"code":"UNAUTHENTICATED"`. No portfolio, no snapshot,
no spend. This is **not** a live CEX IdP.

### 10.4 Finance lab B — negotiated profile (`OAUTH_LAB` only)

Loopback `GET /lab/pkce`, `/lab/authorize`, `/lab/token`, `/lab/dpop` are
**REGTEST OAUTH_LAB**. They are not a partner issuer. Use them only to show
that a bound `ReserveExtensionProfileV1_1` is distinct from `/profile`.

```bash
VERIFIER=pkce-verifier-demo-aaaa
API_BASE=https://exchange.example/btx/hcp/v1

# challenge
curl -sS -o /tmp/cr11-pkce.json \
  "http://127.0.0.1:18781/lab/pkce?verifier=${VERIFIER}"

# authorize (account-demo / client-demo — lab fixtures)
CHALLENGE=$(python3 -c 'import json; print(json.load(open("/tmp/cr11-pkce.json"))["challenge"])')
curl -sS -o /tmp/cr11-auth.json \
  "http://127.0.0.1:18781/lab/authorize?account=account-demo&client_id=client-demo&redirect=https://app.example/cb&state=state-1&challenge=${CHALLENGE}"

CODE=$(python3 -c 'import json; print(json.load(open("/tmp/cr11-auth.json"))["code"])')
curl -sS -o /tmp/cr11-tok.json \
  "http://127.0.0.1:18781/lab/token?code=${CODE}&verifier=${VERIFIER}&redirect=https://app.example/cb"

TOKEN=$(python3 -c 'import json; print(json.load(open("/tmp/cr11-tok.json"))["access_token"])')
curl -sS -o /tmp/cr11-dpop.json \
  "http://127.0.0.1:18781/lab/dpop?htm=GET&htu=${API_BASE}/extensions/cognitive-reserve&access_token=${TOKEN}"

curl -sS -D - -o /tmp/cr11-ext-b.json \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "DPoP: $(python3 -c 'import json; print(json.dumps(json.load(open("/tmp/cr11-dpop.json")), separators=(",", ":")))')" \
  http://127.0.0.1:18781/extensions/cognitive-reserve
```

Pass: HTTP **200**, `object_type` = `ReserveExtensionProfileV1_1`,
`body.extension_id` = `cognitive-reserve`, non-empty
`parent_profile_body_id` bound to this instance’s signed `/profile`.
Repeat the same curls against `:18780` — still **403**
`PROFILE_UNSUPPORTED`. The two origins must disagree on the extension.

A second independently configured `-finance=1` origin (different
`-datadir` / `-instance`) is a **different** parent profile and a
**different** extension binding. Do not replay `client_operation_id`
across providers; cross-provider financial retry is not globally
idempotent.

### 10.5 What these CR11 curls do not prove

Honest **NOT_RUN** (do not report as PASS):

- Live CEX identity provider / live custody HSM / production attestor swap
  (**forbidden**)
- Distinct-person committee quorum against a real IdP
- Concurrent reserve-floor proof against a production ledger
- Native funding/refund round-trip, two-provider customer exit, CR11-J01–J20
- `CLIENT_VERSION_IS_RELEASE=true` — remains **false**

Same two-instance shape (different ports `18790` / `18791`):
`test/functional/feature_modelnet_cr11.py`. Do not run it against production
`btxd`. Do not compile from this document.

Operator notes:
[`doc/hosted/HCP_OPERATOR_NOTES.md`](../../../doc/hosted/HCP_OPERATOR_NOTES.md).
