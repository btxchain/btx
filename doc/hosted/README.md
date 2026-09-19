# Hosted Control Plane (0.34.8-dev)

**Status:** development in this tree. **Not a shipping tag.** Last shipping
release remains **v0.34.7**. `CLIENT_VERSION_IS_RELEASE=false`.

The Hosted Control Plane (HCP/1) is a **third plane**. It is not consensus,
not the Native Model Network helper, and not a public HTTP capability API on
`btxd`. **Cognitive Reserve v1.1** is a **negotiated extension of this plane**,
not a fifth process and not a second `HcpEngine`.

| You are | Start |
|---|---|
| People | [HUMANS.md](../../HUMANS.md) (walletless discovery section) |
| Agents | [AGENTS.md](../../AGENTS.md) (HCP plane) |
| Operators | this file, then the spec |
| Spec | [../modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md](../modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md) |
| Cognitive Reserve v1.1 | [../modelnet/crf/](../modelnet/crf/) (negotiated HCP/1 extension; not a fifth plane) |

## What it is

A conforming gateway exposes **34 typed REST operations** so a customer (or
agent) can discover exact packages, receive a portable handoff, and — only
when a FUNDING profile is actually proven — orchestrate quotes and intents.
Those **34** base operations and the seven original signed object schemas stay
byte-stable. Cognitive Reserve adds **50** operations only after
`GET /extensions/cognitive-reserve` succeeds; a `ProviderProfile` alone does
not imply the extension. Unknown or disabled extension routes return
`PROFILE_UNSUPPORTED` and must **not** fall back to unrestricted funding.
The customer's machine still verifies bytes, applies an owner
`LocalCapabilityGrant`, and runs locally. Automatic BTX spend is **0**.
`CLIENT_VERSION_IS_RELEASE` remains **false**. The production GPU attestor is
not replaced.

Walletless discovery does **not** require opening a monetary wallet, mining,
or a full chain sync. A hosted receipt is `HOSTED_ATTESTED` observation, not
consensus-ready and not `RUNTIME_READY`.

## Processes

| Binary | Role | Must not |
|---|---|---|
| `btxd` | Monetary consensus, wallet templates | OAuth, HCP HTTP, public capability HTTP |
| `btx-modeld` | PQ1 model plane | Public HTTP capability, custody signing, generic `/rpc` |
| `btx-capabilityd` | Owner-local grants, plan/ensure | Hosted finance, OAuth |
| `btx-hcpd` | Loopback/lab gateway: **34** typed ops, lab OAuth; CR11 on the **same** process when the funding-lab preset sets `cr11_enabled` | Consensus, wallet RPC, inbound runtime ports, a fifth plane |
| `btx-hosted` | Walletless preset / connector | Start wallet or mining; custody keys |

OAuth lives in `btx-hcpd` (in-process `OAUTH_LAB`) or a partner IdP. It is
**never** in `btxd`. There is **no** public `/rpc` passthrough.

OpenAPI: `src/modelnet/hcp/schemas/openapi.yaml`.
34 ops: [../../audit/hcp-native-operation-map.csv](../../audit/hcp-native-operation-map.csv).
Authority: [../../audit/hcp-authority-matrix.md](../../audit/hcp-authority-matrix.md).
Zones: [trust-zones.md](trust-zones.md).

## Documents in `doc/modelnet/hcp/`

| File | Role |
|---|---|
| [01_CEX_2030s_Strategy.md](../modelnet/hcp/01_CEX_2030s_Strategy.md) | Strategy paper. Commercial examples are not forecasts. |
| [02_Hosted_Control_Plane_Implementation_Spec.md](../modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md) | Normative HCP/1 (BTX-HCP-001) |
| [03_CEX_Integration_Guide.md](../modelnet/hcp/03_CEX_Integration_Guide.md) | Partner onboarding |
| [ACCEPTANCE_TESTS.md](../modelnet/hcp/ACCEPTANCE_TESTS.md) | 120 cases + J01–J12 catalogue (assignment, not PASS) |

Reference kit (SIMULATION_ONLY): [../../contrib/modelnet/hcp-reference/](../../contrib/modelnet/hcp-reference/).
SDKs (not wallets): [../../contrib/modelnet/hcp-sdk/](../../contrib/modelnet/hcp-sdk/).
Portal shell: [../../contrib/modelnet/hcp-portal/](../../contrib/modelnet/hcp-portal/).
Gateway YAML template only: [../../contrib/modelnet/hcp-gateway/config.example.yaml](../../contrib/modelnet/hcp-gateway/config.example.yaml).

## Cognitive Reserve v1.1 (negotiated HCP/1 extension)

Not a fifth plane. Same `btx-hcpd` / `btx-hosted` processes. Spec:
[../modelnet/crf/02_Cognitive_Reserve_Implementation_Spec.md](../modelnet/crf/02_Cognitive_Reserve_Implementation_Spec.md).
Launch guide: [../modelnet/crf/03_CEX_Integration_and_Launch_Guide.md](../modelnet/crf/03_CEX_Integration_and_Launch_Guide.md).
50 ops: [../../src/modelnet/crf/schemas/OPERATIONS.md](../../src/modelnet/crf/schemas/OPERATIONS.md).
OpenAPI: `src/modelnet/crf/schemas/openapi-v1.1.yaml`. SDKs (not a second
ledger): [../../contrib/modelnet/crf-sdk/](../../contrib/modelnet/crf-sdk/).

| Invariant | This tree |
|---|---|
| Planes | Monetary / Model / Hosted. CR11 rides Hosted. |
| Base HCP ops | **34** preserved |
| Extension ops | 50, only when `ReserveExtensionProfileV1_1` is advertised |
| `automatic_spend_atoms` | **0** |
| Production attestor | **not replaced** |
| `CLIENT_VERSION_IS_RELEASE` | **false** (0.34.8-dev) |

Lab topology is still two independently configured `btx-hcpd` instances
(`127.0.0.1:18780` walletless, optional `:18781` `-finance=1`). The
walletless preset leaves `cr11_enabled=false`. The funding-lab preset turns
the extension on **in-process** — that flag is not live CEX, live HSM, or a
shipping claim. See [HCP_OPERATOR_NOTES.md](HCP_OPERATOR_NOTES.md) and
[../../contrib/modelnet/hcp-gateway/DEMO.md](../../contrib/modelnet/hcp-gateway/DEMO.md).

## Evidence (honest)

Native Boost cases exist in `src/test/modelnet_hcp_*_tests.cpp` (132 cases:
120 family tests + J01–J12). Process E2E scripts exist:

- `test/functional/feature_modelnet_hcp.py` — two loopback gateways + `btx-hosted walletless`
- `test/functional/feature_modelnet_hcp_journeys.py` — J01 / J03 fail-closed / J09 / J11 / J12 slices
- `test/functional/feature_modelnet_cr11.py` — same two-instance shape; walletless `PROFILE_UNSUPPORTED` vs finance-lab `ReserveExtensionProfileV1_1`

In-process `OAUTH_LAB` is **not** a live CEX IdP. Map and gaps:

- [../../audit/hcp-evidence.md](../../audit/hcp-evidence.md)
- [../../audit/hcp-journeys.csv](../../audit/hcp-journeys.csv)
- [../../audit/hcp-requirement-traceability.csv](../../audit/hcp-requirement-traceability.csv)
- [../../audit/hcp-not-run.md](../../audit/hcp-not-run.md)

Cognitive Reserve catalogue (assignment, not PASS):
[../modelnet/crf/ACCEPTANCE_TESTS.md](../modelnet/crf/ACCEPTANCE_TESTS.md),
[../modelnet/crf/JOURNEYS.md](../modelnet/crf/JOURNEYS.md). Honest gaps:
[../../audit/cr11-not-run.md](../../audit/cr11-not-run.md). Baseline freeze:
[../../audit/cr11-baseline.md](../../audit/cr11-baseline.md).

Do not treat this README as live CEX, live HSM, live CUDA DMA, GUI, 400GiB,
uTP, torrentd, or QUIC evidence. QUIC stays **NONSHIPPING**. CR11 journeys
remain **NOT_RUN** until their evidence directories are filled.
