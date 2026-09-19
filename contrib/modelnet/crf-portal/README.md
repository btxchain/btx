# Cognitive Reserve portal (v1.1)

Static capital workspace for HCP/1 + Cognitive Reserve (`index.html` + `portal.js`).
It is **not** a wallet, **not** a CEX, and **not** committee/custody/local-grant
authority. Serve it against a loopback `btx-hcpd` origin (same host/port you
would use for typed `/reserve` and `/capital` calls). Demo fixtures are not
production credentials.

Open `index.html` from this directory (or any static file server). Point
**Gateway origin** at `http://127.0.0.1:18781` (finance lab, CR11 on) or
`http://127.0.0.1:18780` (walletless discovery). Live `fetch` may be blocked
if the gateway sends no CORS headers; curl against the same paths remains the
reliable loopback proof. A real browser pass against a live gateway is
**NOT_RUN**.

## Six primary screens (CR11-UX-01)

| Screen | Person can | Must not |
|---|---|---|
| **Overview** | See reserve / committed / holdings; keep legal payer + portfolio visible | Merge holdings into cash NAV; treat group view as pooled funds |
| **Reserves** | Preview SUGGEST policy; load `GET /reserve/portfolios/{id}/snapshot` | Execute a trade from preview; debit from family view |
| **Capabilities** | Public free acquisition; search catalogue; list positions | Require CEX payment, new wallet, or subscription for public capability |
| **Build** | List/create programmes; join (membership only); prepare commitment | Treat membership as a debit |
| **Approvals** | One packet: payer, portfolio, objective, max debit, reserve, local effect | Per-leg extra prompts; adviser self-debit; family-view execute |
| **Activity** | Two lanes (money vs readiness); view existing operation | **Retry-new-payment** CTA on UNKNOWN / HTTP 202 |

Secondary: **Reports** (`POST /capital/reports`, `POST /capital/exports`) and
**Gateway** (origin, lab session, `GET /health`).

## Persistent payer (CR11-UX-02)

The legal payer and portfolio stay in the header on every screen and are
copied onto the decision packet. Changing payer or portfolio **clears** the
previous review so a packet cannot execute under a stale entity.

## One decision packet (CR11-UX-03 / UX-04)

Create capital plan → one packet with financial exposure and a **separate**
local permission. Financial approval cannot stand in for the device grant.
Adviser role is draft-only. Duplicate execute clicks disable the control and
reuse `client_operation_id` (CR11-UX-05).

## Family / group view is not debit authority

The group-overview checkbox is visibility only. Execute, financial debit
approval, and AUTO replenishment stay off. Gateway list payloads that include
`family_view_debit` are still treated as non-debit in this shell.

## Unknown broadcast (CR11-UX-06)

HTTP **202**, `BROADCAST_UNKNOWN`, and `RECONCILIATION_REQUIRED` show:

> Transaction outcome is being reconciled. The hold is retained. View the
> existing operation. Do not start a new payment.

There is **no** “retry payment” / “retry new payment” control. Safe action is
`GET` the existing `/capital/executions/{id}` or `/capital/allocations/{id}`.

## Free public journey (CR11-UX-10)

**Prepare locally** / catalogue search do not attach a financial allocation.
Copy states that no exchange payment, new wallet, or forced subscription is
required. `automatic_spend_atoms` stays **0**. Walletless `:18780` is the
discovery origin; `/reserve/*` may 403 there (`PROFILE_UNSUPPORTED`).

## No custody keys, no token-in-URI

- Tokens live in the password field and go out as `Authorization: Bearer` only.
- Needles `access_token`, `dpop`, `bearer`, … are refused on the page URL and
  on constructed request URLs. A planted query is stripped via `history.replaceState`.
- Lab session uses `/lab/pkce`, `/lab/authorize`, `/lab/token` **without**
  putting the access token on a URI. DPoP JSON is built in-page (`jkt` + SHA-256
  `ath`). This page never calls `/lab/dpop?access_token=`.
- Draft **identifiers** may sit in `sessionStorage`. Tokens do not.
- Session 401: retain draft, ask for re-auth, recheck the current plan
  (CR11-UX-08).

## Locale (CR11-UX-09)

English / 日本語 toggles `Intl` display. Submit bodies keep canonical atom and
decimal **strings**. Payer names and amounts use `overflow-wrap`; they are not
ellipsis-truncated.

## Accessibility (CR11-UX-07)

Practical WCAG 2.2 AA in static HTML/JS: skip link, labelled controls, 44px
targets, visible `:focus-visible`, `aria-current`, `role="status"` / `aria-live`,
dialog labelled + focus return, status text (not colour alone). A browser
checkbox is still not a screen-reader-certified lab; that evidence stays
**NOT_RUN**.

## Routes (same origin as `btx-hcpd`)

`btx-hcpd` also accepts the `/btx/hcp/v1` prefix; this portal calls the
stripped CR11 paths the daemon implements:

| Method | Path |
|---|---|
| GET | `/health`, `/extensions/cognitive-reserve` |
| GET | `/reserve/entities/links`, `/reserve/portfolios`, `/reserve/portfolios/{id}/snapshot` |
| POST | `/reserve/policies`, `/reserve/replenishment/plans` |
| POST | `/capital/workloads`, `/capital/comparisons`, `/capital/plans`, `/capital/allocations` |
| POST | `/capital/allocations/{id}/execute` |
| GET | `/capital/allocations/{id}`, `/capital/executions/{id}` |
| GET/POST | `/capital/programs`, `…/memberships`, `…/commitments` |
| GET | `/capital/positions`, `/capital/products` |
| POST | `/capital/products/{id}/referral`, `/capital/reports`, `/capital/exports` |
| POST | `/capabilities/search` (public catalogue; not a payment) |
| GET | `/lab/pkce`, `/lab/authorize`, `/lab/token` (REGTEST lab JSON only) |

Finance mutations need a DPoP-bound lab token. Public catalogue search may be
unauthenticated. This page never sets `automatic_spend_atoms` and never
auto-submits on timeout or 202.

## NOT_RUN

| Item | Why |
|---|---|
| Live browser vs live `btx-hcpd` | No CORS on the daemon; file:// / other-port `fetch` is blocked. Evidence: `audit/cr11-native-acceptance.csv` CR11-UX-01–10 **NOT_RUN**. |
| Screen-reader / keyboard lab | Needs an accessibility lab recording (`evidence/CR11-UX-07/`). |
| Distinct-person committee quorum | Single lab token cannot complete native two-person `Cr11Approved`. |
| Production IdP / HSM / mainnet | Out of scope. Loopback REGTEST only. |

Python/TypeScript clients under `contrib/modelnet/crf-sdk/` are the typed
SDKs for agents. `automatic_spend_atoms` stays **0**.
