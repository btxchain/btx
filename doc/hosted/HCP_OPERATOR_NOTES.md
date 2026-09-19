# HCP operator notes (0.34.8-dev)

**Status:** development notes for the Hosted Control Plane (`btx-hcpd` /
`btx-hosted`). Last shipping release remains **v0.34.7**. This file is not a
go-live certificate.

HCP is a **third plane**. It is not consensus, not ExactReplay, and not a
wallet RPC proxy. `automatic_spend_atoms` stays **0**. Bind is **loopback**
in the lab kit (`127.0.0.1` only).

Companion:

- Lab demo: [`contrib/modelnet/hcp-gateway/DEMO.md`](../../contrib/modelnet/hcp-gateway/DEMO.md)
- Two-instance launcher: [`contrib/modelnet/hcp-gateway/run-two-instances.sh`](../../contrib/modelnet/hcp-gateway/run-two-instances.sh)
- Zones: [`trust-zones.md`](trust-zones.md)
- Spec: [`../modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md`](../modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md)
- Honest gaps: [`../../audit/hcp-not-run.md`](../../audit/hcp-not-run.md)

## Never

- Do **not** replace the CUDA GPU attestor `btxd.real` (including
  `~/.local/opt/btx-0.33.2/libexec/btxd.real` or any live signer prefix).
- Do **not** `systemctl --user stop` / `restart` production `btxd`.
- Do **not** SIGKILL production `btxd`.
- Do **not** run CUDA goldens, HCP DMA labs, or `ninja -j` that starve the
  live GPU.
- Do **not** bind `btx-hcpd` to a non-loopback address in this kit
  (`0.0.0.0`, LAN, public IP). The daemon refuses anything other than
  `127.0.0.1` / `localhost`.
- Do **not** advertise FUNDING because a market or catalogue exists.
- Do **not** report in-process `OAUTH_LAB`, `BTX_NATIVE_TEMPLATES`, or the
  LOCAL-06 fence as live partner / hardware PASS.

## Rollout order

Profiles are **cumulative**. Enable and prove them in this order. Skip
nothing because a later flag is easier to set.

```text
DISCOVERY  →  HANDOFF  →  FUNDING
```

CUSTODY evidence is a **FUNDING prerequisite**, not a substitute for
DISCOVERY/HANDOFF. FLEET is opt-in after HANDOFF and does not unlock money.

| Stage | Advertise | What must be true | Lab stand-in (not a substitute) |
|---|---|---|---|
| **1. DISCOVERY** | Public `GET /profile`, catalogue search, exact package bytes | Walletless path works with **no** monetary wallet, mining, or full chain sync. `automatic_spend_atoms=0`. Generic `/rpc` stays 404. | Loopback `btx-hcpd -walletless` on `127.0.0.1:18780` |
| **2. HANDOFF** | Portable `CapabilityHandoff`, device pair/confirm/revoke, export | Owner `LocalCapabilityGrant` is required before local ensure. Handoff is not a wallet. Browser has no custody keys; pairing is outbound; no token in URI. | `btx-hosted walletless` + HANDOFF ops on the same walletless instance |
| **3. FUNDING** | Quotes, intents, authorize/submit/cancel, receipts | Live (or test-network) custody + native templates proven. DPoP-or-mTLS on finance. HTTP 202 is UNKNOWN, not settlement. No auto-spend. | Optional `btx-hcpd -finance=1` on `127.0.0.1:18781` (**lab only**) |

A venue may stop after DISCOVERY. It may stop after HANDOFF. It must **not**
jump to FUNDING.

Mapped to the CEX guide stages: DISCOVERY ≈ internal catalogue sandbox
(no money); HANDOFF ≈ partner device/acquisition pilot; FUNDING ≈ native
economic lab then limited customer funding. Those later stages remain
**NOT_RUN** until the rows below are actually executed.

## Lab topology (this tree)

Two independently configured processes plus one local connector. Distinct
`-datadir` and `-instance`. Flags `-walletless` / `-finance=1` replace the
whole preset — pass them **before** `-datadir` / `-instance`.

| Bind | Role |
|---|---|
| `127.0.0.1:18780` | Walletless DISCOVERY + HANDOFF |
| `127.0.0.1:18781` | Optional `-finance=1` FUNDING lab |
| (no HTTP) | `btx-hosted walletless` |

Binaries: `$BUILDDIR/bin` if `BUILDDIR` is set and contains `btx-hcpd`, else
`$HOME/.local/opt/btx-0.34.8-regtest/bin` if that prefix exists. Do not ninja
from the demo script.

Unauthenticated finance:

- Walletless A: HTTP **403** `FUNDING_DISABLED`
- Finance lab B without bearer: HTTP **401** `UNAUTHENTICATED`

That fail-closed behaviour is the intended demonstration, not a missing
password. It is **not** live CEX enrollment.

## Honest NOT_RUN

Do not mark these PASS. Native Boost cases and process E2E **scripts** can
exist without closing the row.

| Gap | Status | Why it is still NOT_RUN |
|---|---|---|
| **Live CEX IdP** | **NOT_RUN** | In-process `OAUTH_LAB` (`LabAuthorize` / `LabToken` / `LabDpop`) is not a partner issuer, not browser sessions, not production token metadata. |
| **Live custody HSM** | **NOT_RUN** | `-finance=1` uses `HcpFundingLabPreset` + `BTX_NATIVE_TEMPLATES`. No hardware signer, no production custody adapter. |
| **Live CUDA** | **NOT_RUN** | LOCAL-06 exercises a DMA **fence** without a device. No GPU transfer, no attestor GPU, no isolated CUDA worker for HCP. Do not run CUDA goldens against the live signer GPU. |
| Production `btxd.real` | **must not replace** | The CUDA GPU attestor stays on its current binary. HCP does not overwrite it. |
| Second `WITH_MODELNET=OFF` cmake tree | **NOT_RUN** | Disk policy: one Release compile tree. |
| QUIC | **NONSHIPPING** | Do not advertise. |

Go-live manifest (`GoLiveManifest`) must expose claimed vs proven profiles
and keep `production_binary_replaced: false`. A backend flag is not proof.

## Production attestor (unchanged)

The live GPU / attestation authority remains a **separate** `btxd` process
from `btx-hcpd`. HCP rollout does not:

- swap `btxd.real`
- load attestor WIFs into the gateway
- treat a `FinancialReceipt` as consensus-ready or `RUNTIME_READY`
- skip ExactReplay because a hosted receipt exists

If an HCP change appears to require a production signer restart, **stop**
and flag the operator. Prefer a second path so the live node never stops.

## Operator checklist before advertising a profile

**DISCOVERY**

- [ ] Loopback (or production HTTPS edge) `GET /profile` is a signed
      `ProviderProfile` with only proven `supported_profiles`
- [ ] `POST /capabilities/search` does not invent capacity (`incomplete`
      stays honest)
- [ ] `POST /rpc` is 404 `GENERIC_RPC_DISABLED`
- [ ] Walletless client: `start_wallet=false`, `start_mining=false`,
      `automatic_spend_atoms=0`

**HANDOFF** (after DISCOVERY)

- [ ] Device pairing is owner-approved, outbound, no token-in-URI
- [ ] Accepting a handoff requires `LocalCapabilityGrant`
- [ ] HostedAccountPolicy cannot launch local runtime
- [ ] Export/disconnect does not rewrite public package identity

**FUNDING** (after HANDOFF + custody evidence)

- [ ] Live CEX IdP **or** an independently reviewed test IdP — until then
      **NOT_RUN**
- [ ] Live HSM / approved custody backend — until then **NOT_RUN**
- [ ] Native test-network (or mainnet, if that is the product) confirm/reorg
      drills — in-process `SetNativeConfirmations` is **not** that drill
- [ ] Finance requires DPoP or mTLS; 202 UNKNOWN retains the hold; no
      auto-submit; `automatic_spend_atoms` remains 0
- [ ] Rollback stops **new** work and keeps refund/reconciliation
      obligations

## Failure posture (all stages)

On provider outage: keep local public capability running; pause new hosted
finance; do not fail over pending intents to another exchange.

On signer ambiguity or unknown broadcast: retain reservation, do not
auto-retry a replacement spend, reconcile `client_operation_id`.

On production incident: leave the CUDA attestor running. HCP PIDs are
separate; SIGTERM only lab `btx-hcpd` you started.

## Launch approval (blank until filled by a human)

Provider / legal venue: ____  
Candidate fingerprint: ____  
Profiles enabled and **proven** (not merely flagged): ____  
Native network / genesis: ____  
Custody / refund controller: ____  
Live CEX IdP evidence (or **NOT_RUN**): ____  
Live HSM evidence (or **NOT_RUN**): ____  
Live CUDA / attestor binary left in place: ____  
Independent security reviewer: ____  
Operator approval / date: ____

---

## Cognitive Reserve v1.1 (append — 0.34.8-dev)

**Status:** negotiated HCP/1 extension notes. **Not a fifth plane.** Last
shipping release remains **v0.34.7**. `CLIENT_VERSION_IS_RELEASE` remains
**false**. `automatic_spend_atoms` stays **0**. This section is not a go-live
certificate.

Cognitive Reserve rides `btx-hcpd` / `btx-hosted`. It is **not** consensus,
not ExactReplay, not a second customer ledger, not Core v4, and not a new
`HcpEngine`. The original **34** HCP operations and seven signed object
schemas stay byte-stable. Fifty additive `/reserve/*` and `/capital/*`
operations exist only after `GET /extensions/cognitive-reserve` returns a
signed `ReserveExtensionProfileV1_1` bound to the enrolled parent
`ProviderProfile` body ID. A profile advertisement without that extension
object is **not** support.

Companion (unchanged topology):

- Lab demo (CR11 two-instance curls): [`contrib/modelnet/hcp-gateway/DEMO.md`](../../contrib/modelnet/hcp-gateway/DEMO.md)
- Spec: [`../modelnet/crf/02_Cognitive_Reserve_Implementation_Spec.md`](../modelnet/crf/02_Cognitive_Reserve_Implementation_Spec.md)
- Ops: [`../../src/modelnet/crf/schemas/OPERATIONS.md`](../../src/modelnet/crf/schemas/OPERATIONS.md)
- Honest gaps: [`../../audit/cr11-not-run.md`](../../audit/cr11-not-run.md)

### Never (CR11)

- Do **not** treat Cognitive Reserve as a fifth process or a new coin.
- Do **not** rewrite the 34 base HCP routes to “make room” for reserve ops.
- Do **not** silently approximate a reserve, committee, or programme call
  with unrestricted old FUNDING. Unknown/disabled extension →
  `PROFILE_UNSUPPORTED`.
- Do **not** treat family/group view as debit authority.
- Do **not** put pending deposits, expected refunds, sibling-entity funds,
  forecast savings, or cognitive holdings into AVAILABLE `E`. Do not
  double-subtract existing holds. Capacity is `max(0, min(E - P, R))` with
  checked integers.
- Do **not** merge model size, expected research success, or copy counts
  into liquid reserve NAV (`nav_merged` stays false).
- Do **not** auto-retry an uncertain conversion or native broadcast. HTTP
  202 remains UNKNOWN. Reuse `client_operation_id`.
- Do **not** invent Core v4. Portable packages stay Core v3 +
  `CAPABILITY_HANDOFF_V1`.
- Do **not** replace the CUDA GPU attestor `btxd.real`. Do **not**
  `systemctl --user stop` / `restart` production `btxd`. Do **not** SIGKILL
  production `btxd`.
- Do **not** bind non-loopback in this kit. Do **not** ninja from the demo
  script. Do **not** bump `IS_RELEASE`.

### Lab topology (same two instances)

The CR11 gate is **per process**, independently configured. Distinct
`-datadir` and `-instance`. Flags `-walletless` / `-finance=1` still replace
the whole preset — pass them **before** `-datadir` / `-instance`. In this
tree the walletless preset leaves `cr11_enabled=false`; `-finance=1` sets
`cr11_enabled=true`. That lab flag is **not** live CEX IdP, live HSM, or
production custody.

| Bind | Preset | `GET /health` `cognitive_reserve` | `GET /extensions/cognitive-reserve` |
|---|---|---|---|
| `127.0.0.1:18780` | `-walletless` | `false` | HTTP **403** `PROFILE_UNSUPPORTED` (even before a token is considered) |
| `127.0.0.1:18781` | `-finance=1` | `true` | HTTP **401** `UNAUTHENTICATED` without DPoP bearer; HTTP **200** `ReserveExtensionProfileV1_1` with in-process `OAUTH_LAB` |

Base `/profile` stays HTTP 200 on both. `/rpc` stays HTTP **404**
`GENERIC_RPC_DISABLED` on both. `automatic_spend_atoms` is **0** on both.
The two origins do **not** share catalogue, ledger, OAuth, reserve, or
committee state. Financial children still reuse existing `FinanceIntent`;
local children still reuse `CapabilityHandoff`.

Unauthenticated finance behaviour from the HCP notes is unchanged. CR11
does not open a wallet, start mining, or skip ExactReplay because a
`ReserveSnapshotV1_1` exists.

### Rollout order (extension after proven HCP profiles)

```text
DISCOVERY  →  HANDOFF  →  FUNDING  →  advertise Cognitive Reserve
```

Do not advertise reserve/committee/programme features because a market or
catalogue exists. Do not jump the HCP stages. Disabling the extension must
stop **new** capital creation/execution while preserving accepted child
intents, holds, refunds, event/export access, and local generation safety.

| Stage | Advertise | What must be true | Lab stand-in (not a substitute) |
|---|---|---|---|
| **4. Cognitive Reserve** | Signed `ReserveExtensionProfileV1_1`, schema/operations digests bound to the parent profile | DISCOVERY + HANDOFF proven. FUNDING only with custody evidence. Distinct-person quorum. Family view is read-only. Capacity formula holds under concurrency. No auto-spend. Rollback path exists. | Optional `-finance=1` instance on `127.0.0.1:18781` (`cr11_enabled` in-process). `OAUTH_LAB` is **not** a partner issuer. |

Mapped to the CEX Cognitive Reserve guide: advertise the extension only
after mapping existing HCP adapters, then run two-provider + walletless
journeys. Those journeys remain **NOT_RUN** until evidence directories are
filled.

### Operator checklist before advertising the extension

- [ ] `GET /profile` still serves the original ProviderProfile (34-op
      catalogue unchanged)
- [ ] `POST /rpc` is still 404 `GENERIC_RPC_DISABLED`
- [ ] Walletless origin: `cognitive_reserve=false`, extension routes
      `PROFILE_UNSUPPORTED`, `automatic_spend_atoms=0`,
      `start_wallet=false`, `start_mining=false`
- [ ] Enrolled origin: `ReserveExtensionProfileV1_1.parent_profile_body_id`
      matches the current signed profile; substituting another digest fails
      closed
- [ ] Old clients keep base DISCOVERY/HANDOFF; they never see a silent
      funding fallback for reserve ops
- [ ] Family/group overview cannot debit; payer is an explicit legal entity
- [ ] Allocation plans: ≤32 legs, depth ≤16, cycles rejected
- [ ] Approval counts distinct verified people (two sessions of one person
      are one seat). Committee approval is not a `LocalCapabilityGrant`.
- [ ] Refunds restore balance and do **not** replenish lifetime mandate
      unless a separately approved policy says so
- [ ] Live CEX IdP / live HSM / live CUDA — until then **NOT_RUN**
- [ ] Production `btxd.real` left in place (`production_binary_replaced:
      false`)
- [ ] `CLIENT_VERSION_IS_RELEASE` still **false**

### Failure posture (CR11)

On extension disable or rollback: keep local public capability running;
pause new reserve/committee execution; reconcile accepted children; do not
fail over pending intents to another exchange.

On signer ambiguity or unknown conversion: retain reservation and acquired
BTX; do not auto-reverse or auto-retry a replacement spend.

On production incident: leave the CUDA attestor running. SIGTERM only lab
`btx-hcpd` PIDs you started.

### Launch approval extras (blank until filled by a human)

Cognitive Reserve advertised (or **NOT_RUN**): ____  
Parent `ProviderProfile` body ID / extension binding: ____  
Two independently configured origins demonstrated: ____  
`automatic_spend_atoms=0` on both: ____  
Production attestor left in place: ____  
`CLIENT_VERSION_IS_RELEASE=false`: ____
