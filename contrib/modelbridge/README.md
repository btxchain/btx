# Optional disclosed-weaker browser bridge (v1.1 D09 / §12.1)

This directory is **not** `btx-modeld`. Native PQ1 stays strict inside the
helper. Operators who need a PQ-only deployment **omit this process**.

`capabilities.browser_bridge` in the native catalog remains **false** until
an operator starts this loopback server. This tree does not flip
`catalog.cpp`. Feature bits (`RESOURCE_RESOLVE=1` … `PRESERVATION_CIRCLE=64`,
reported as 127) are **native helper** caps, not browser-bridge features.

## What it is

A separately deployed loopback HTTP edge for browsers that cannot speak PQ1.
The **browser-facing** hop MAY be conventional HTTP(S) and MUST disclose that
it is **not** end-to-end post-quantum. Upstream to BTX is still PQ1 or unix
RPC to `btx-modeld`. There is no native-client TLS fallback.

Every JSON object includes:

| Field | Value | Meaning |
|---|---|---|
| `pq_end_to_end` | `false` | Browser hop is not PQ |
| `native_fallback` | `false` | Helper does not downgrade to classical TLS |
| `wallet` | `false` | No wallet RPC, secrets, BanMan, or spend |

JSON responses also send `Content-Security-Policy: default-src 'none'`
(same policy as `FillJson` in `http_bridge.cpp`). Public DNS 42/43 is
`DnsSplit42_43` in that C++ library: `{left}.{right}.{zone}`. Native helper
stays PQ1.

## Native C++ (not this process)

`src/modelnet/http_bridge.cpp` implements `HandleBridgeGet` /
`HandleBridgeRequest`. Those functions decode `btx://`, serve `/health` and
`/open?uri=`, and refuse `/wallet`, `/sign`, `/dump` plus POST wallet methods
(405 mutating, 403/404 GET). They are unit-tested in
`src/test/modelnet_bridge_tests.cpp`. They are **not** registered on the
helper’s PQ1 listener.

Production retrieval is **unix RPC** `getmodel` / `listmodels` on
`btx-modeld`, not this HTTP origin.

## How to run

Loopback only. Default bind is `127.0.0.1`. There is no `0.0.0.0` default.

```bash
python3 contrib/modelbridge/modelbridge.py --help
python3 contrib/modelbridge/modelbridge.py --port 18747
# optional: consult the helper catalog (never wallet RPC)
python3 contrib/modelbridge/modelbridge.py --rpc-socket /path/to/modeld.sock
```

```
GET  http://127.0.0.1:18747/health
GET  http://127.0.0.1:18747/open?uri=btx://<85-char-token>
GET  http://127.0.0.1:18747/<token>          # same decode as HandleBridgeGet
```

POST `/wallet`, `/sign`, `/dump`, or a JSON-RPC wallet method is refused.

## Do not

- Bind `0.0.0.0` or treat this as a public origin
- Call wallet RPC, dump keys, sign, or spend
- Claim end-to-end PQ, identity authority, or native catalog advertisement
- Restore classical TLS inside `btx-modeld`

See [doc/modelnet/browser-bridge.md](../../doc/modelnet/browser-bridge.md).
