# Optional browser bridge (v1.1 D09 / §12.1)

Native-only remains a valid 0.34.7 deployment. If an operator **advertises**
this optional disclosed-weaker browser edge, it must pass its own tests.
Omitting the bridge is the PQ-only profile.

## Boundary

| Edge | Allowed | Claim |
|---|---|---|
| Native `btx-modeld` | PQ1 only (ML-KEM-768, ML-DSA-44, AES-256-GCM-SHA384) | End-to-end PQ for that hop |
| Browser HTTP(S) | Conventional HTTP at a **separately deployed** loopback process | Explicitly **not** end-to-end PQ |
| Bridge → BTX | PQ1, or unix RPC to the helper (`getmodel` / `listmodels`) | Never a native-client TLS fallback |

D09 is not permission to restore classical TLS inside `btx-modeld`. The
bridge is never wallet RPC, never a release of secrets, never BanMan, and
never a spend path.

This tree: `capabilities.browser_bridge=false` in the **native catalog**.
Starting `contrib/modelbridge/modelbridge.py` does not flip that bit. Feature
bits (`RESOURCE_RESOLVE=1`, `FREE_GRANT=2`, `SERVICE_RECEIPT=4`,
`RESEARCH_IDENTITY=8`, `COLLECTIONS_ALIAS=16`, `POLICY_BUNDLE=32`,
`PRESERVATION_CIRCLE=64`) are native helper caps, not browser-bridge
features.

## Process split

```
  browser
     |  conventional HTTP (disclosed weaker)
     v
  contrib/modelbridge (127.0.0.1 only; separate process)
     |  unix RPC getmodel/listmodels  --or--  decode only
     v
  btx-modeld  (strict PQ1)     btxd (monetary; untouched)
```

Default bind is **127.0.0.1**. There is no `0.0.0.0` default. The Python
server refuses non-loopback hosts.

## HTTP surface

Implemented twice so the unit tests do not need a live socket:

- Native decode: `HandleBridgeGet` / `HandleBridgeRequest` in
  `src/modelnet/http_bridge.cpp` (not registered on the helper PQ1 listener).
- Loopback server: `contrib/modelbridge/modelbridge.py`.

| Method | Path | Result |
|---|---|---|
| GET/HEAD | `/health` | JSON status + disclosure fields |
| GET/HEAD | `/open?uri=` | Canonical `btx://` JSON (HandleBridgeGet decode) |
| GET/HEAD | `/<token>` | Same decode as a bare Bech32m token |
| GET | `/wallet`, `/sign`, `/dump` (any case) | 403 |
| POST/PUT/PATCH/DELETE | wallet-like path or wallet JSON-RPC method | 405 |
| GET | malformed URI | 400 |

Every JSON body includes `pq_end_to_end: false`, `native_fallback: false`,
`wallet: false` (tests accept mixed-case spellings of those keys). The note
states the HTTP bridge is not the identity authority; verify the native
SHA-384 hash.

`/open` does not fetch bytes. Production retrieve is unix RPC `getmodel` on
`btx-modeld`. Optional `--rpc-socket` may call `listmodels` only.

## Tests

`src/test/modelnet_bridge_tests.cpp` (built when `WITH_MODELNET`):

- malformed URI → 400
- valid URI → canonical
- wallet paths → 403/404 (mutating → 405)
- mixed-case disclosure fields present

## Run

```bash
python3 contrib/modelbridge/modelbridge.py --help
python3 contrib/modelbridge/modelbridge.py          # 127.0.0.1:18747
```

See [contrib/modelbridge/README.md](../../contrib/modelbridge/README.md) and
[web-bridge-boundary.md](web-bridge-boundary.md) (public DNS 42/43 is
implemented; native helper stays PQ1).
