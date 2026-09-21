# BTX HCP reference portal

Static reference UI for the Hosted Control Plane (`index.html` + `portal.js`).
It is a catalogue and pairing shell, not a wallet, not a CEX, and not a
consensus client. Serve it only against a loopback or lab gateway. Demo
fixtures are not production credentials.

Contract: `src/modelnet/hcp/schemas/openapi.yaml`.
Authority: `audit/hcp-authority-matrix.md`. Spec: `doc/modelnet/hcp/`.
Two-instance lab: `contrib/modelnet/hcp-gateway/DEMO.md`.

Open `index.html` from this directory (or any static file server). Point the
origin field at `http://127.0.0.1:18780` (walletless) or
`http://127.0.0.1:18781` (finance lab). Live `fetch` may be blocked by the
browser if the gateway sends no CORS headers; the curl steps in DEMO.md are
the reliable loopback proof. Fixtures on this page are labelled as such.

## Catalogue vs protocol facts

Search hits, sponsored ranks, trending lists and curation badges are **catalogue
annotations**. They are product observations (`observed_at`, coverage, freshness)
and never become package identity, terms IDs, funding authority, or local
runtime admission.

Protocol facts stay on signed HCP objects and native verification: package core
ID, recipe ID, body_id, exact `.btx` bytes, and independently checked terms.
A ranking string cannot widen HostedAccountPolicy or LocalCapabilityGrant.
The portal renders ranking copy in a separate “catalogue annotation” pane,
never mixed into the protocol-fact list.

## Browser has no custody keys

Browser code **cannot** possess custody-signing keys, wallet seeds, ML-DSA
provider spend material, or native wallet RPC. It must not call `btxd` /
wallet RPCs, broadcast transactions, or set `automatic_spend_atoms` away from
**0**. Financial mutations require a DPoP- or mTLS-bound token at the gateway,
not a key in `localStorage`. A FinancialReceipt on this page is HOSTED_ATTESTED
observation, not consensus-ready and not RUNTIME_READY.

The optional token field is a gateway access token only (header `Authorization`).
It is not a spend key. `portal.js` refuses `access_token` / `dpop` / Bearer
material in the page URL, query, fragment, and pairing URI, and strips those
needles from `location` if a deeplink tried to plant them.

## Pairing is outbound-only

The device creates its own key and a short-lived pairing challenge. The
authenticated account approves that exact device. The device then **dials out**
or polls for addressed handoffs (`GET /devices/{device_id}/handoffs`).

- No inbound runtime port on the local daemon.
- No browser-to-unrestricted-localhost privileged route.
- No cross-account device command.
- Ready is shown only after an authorized coarse device report — never inferred
  from a funding receipt, download count, or a live socket.

Revoke pairing from the account; already-dispatched financial effects stay on
reconciliation, not silent replay.

## No token in URI

OAuth access tokens, refresh tokens, DPoP proofs and authorization codes stay
out of the URL bar, query string, fragment, custom URI schemes, and pairing
deeplinks. Use header-bound tokens on the gateway origin only. Do not put
`access_token=` on `/pair?...`. The Devices view builds
`btx-hcp-pair://device/enroll?device_id=&challenge=` and a control that
attempts `&access_token=` is refused. Agent MCP wrappers in
`hcp-sdk/python/mcp_wrapper.py` refuse the same leak toward child tools.

## HTTP 202 is UNKNOWN

HTTP **202** is accepted asynchronous work / UNKNOWN, not settlement. The
Treasury view never auto-submits a finance intent on timeout, lost response, or
202. Reuse the same client-operation ID. Submit stays an explicit, separately
disabled control.

## Views

| View | May | Must not |
|---|---|---|
| Catalogue / search | Public capability hits | Treat rank as protocol |
| Package / terms / quote | Show exact IDs, terms_id, atom strings | Rewrite `.btx` bytes; treat economy % as current terms |
| Treasury / activity | Display holds and UNKNOWN | Auto-submit on timeout or 202 |
| Approvals | Finite policy digest; bind body_id + revision | Expand limits from model text |
| Devices | Outbound pair, handoff poll, revoke | Inbound port, token-in-URI |
| Progress | Stages; Ready only after device report | Infer Ready from receipt/download/socket |
| Export | Public state + custody obligations | Claim self-custody or include secrets |

Python/TypeScript SDKs under `contrib/modelnet/hcp-sdk/` are the typed clients
for both this portal and example agents. `automatic_spend_atoms` stays **0**.
