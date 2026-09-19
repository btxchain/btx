# BTX HCP gateway lab kit

Loopback Hosted Control Plane gateway notes for `btx-hcpd` (0.34.8-dev,
**HCP/1+CR11**). This directory is a **design template plus a two-instance
REGTEST demo**. It is not a production CEX, not consensus, and not a wallet
RPC proxy.

**Cognitive Reserve v1.1 is not a second gateway.** `-finance=1` enables
CR11 on the **existing** `btx-hcpd` binary (`HcpFundingLabPreset` sets
`cr11_enabled`). `btx-hcpd -version` prints `HCP/1+CR11`. This kit does not
ship, compile, or launch a duplicate daemon. Do not ninja from here. Do not
replace production `btxd`.

| Asset | Role |
|---|---|
| `config.example.yaml` | Design template. `simulation_only: true`. Finance **off**. `automatic_spend_atoms: '0'`. `btx-hcpd` does not load this file. |
| `DEMO.md` | Exact curl for two independent processes + `btx-hosted walletless`. |
| `run-two-instances.sh` | Starts those processes on loopback, waits for `/profile`, prints DEMO + CR11 fail-closed curls, SIGTERM cleanup. |

Binaries live in `<tree>/build-gcc13/bin/` (`btx-hcpd`, `btx-hosted`). One
`btx-hcpd` binary, started twice with independent flags/datadirs. Do not
compile from this kit.

## Authority

See `audit/hcp-authority-matrix.md`. `btx-hcpd` may serve the 34 typed REST
operations, and when `-finance=1` the additive CR11 `/reserve` and `/capital`
routes, on **loopback**. It must not:

- proxy generic `/rpc` (HTTP 404 `GENERIC_RPC_DISABLED`)
- start a wallet or miner
- open an inbound runtime port
- auto-spend (`automatic_spend_atoms` stays 0)
- treat HTTP 202 as settlement
- bind anything other than `127.0.0.1` / `localhost`

`btx-hosted walletless` is the local connector: accept/plan/ensure under an
owner grant. It does not hold CEX custody keys. It is not an HTTP server.

## Cognitive Reserve v1.1 on existing `btx-hcpd`

CR11 is a **negotiated HCP/1 extension** in the same process, not a fifth
plane and not a second product.

| Preset | Flag | `cr11_enabled` | `/reserve/*` and `/capital/*` |
|---|---|---|---|
| Walletless (default) | `-walletless` | false | HTTP **403** `"code":"PROFILE_UNSUPPORTED"` |
| Finance lab | `-finance=1` | true | Extension on (auth still fail-closes without DPoP bearer) |

Walletless must **not** silently fall back to unrestricted FUNDING. The
same 403 applies to `GET /extensions/cognitive-reserve`. `GET /health`
reports `"cognitive_reserve": false` on walletless and `true` on `-finance=1`.

Unauthenticated finance on the CR11 instance is **401** `UNAUTHENTICATED`
(profile is on; credentials are not). That is distinct from walletless
`PROFILE_UNSUPPORTED`.

## Two independently configured instances + one local client

This topology is **required**. One process is not enough: walletless and
finance/CR11 are independently configured origins (distinct `-datadir`,
`-instance`, bind, preset). The local client is a third participant with no
HTTP bind.

| | Walletless | Finance / CR11 lab | Local client |
|---|---|---|---|
| Bind | `127.0.0.1:18780` | `127.0.0.1:18781` | none |
| Binary | `btx-hcpd` | **same** `btx-hcpd` | `btx-hosted` |
| Flag | `-walletless` (default) | `-finance=1` | `walletless` |
| `-instance` | `hcp-a` | `hcp-b` | — |
| `-datadir` | distinct | distinct | — |
| Finance | 403 `FUNDING_DISABLED` | 401 `UNAUTHENTICATED` without DPoP bearer | does not spend |
| CR11 `/reserve`, `/capital` | 403 `PROFILE_UNSUPPORTED` | extension enabled | not a gateway |

Put `-walletless` / `-finance=1` **before** `-datadir` and `-instance`
(those flags replace the whole preset). Isolated REGTEST / **loopback only**.
Do not pass `-bind=0.0.0.0`, a LAN address, or a public interface.

```bash
bash contrib/modelnet/hcp-gateway/run-two-instances.sh
```

Reference UI: `contrib/modelnet/hcp-portal/` (base HCP) and
`contrib/modelnet/crf-portal/` (CR11 shell; template only). Contract:
`src/modelnet/hcp/schemas/openapi.yaml` plus additive
`src/modelnet/crf/schemas/openapi-v1.1.yaml`. Spec: `doc/modelnet/hcp/` and
`doc/modelnet/crf/`.
