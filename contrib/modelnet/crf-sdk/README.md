# SDK integration

Cognitive Reserve v1.1 typed clients are an **additive HCP/1 extension** (50
operations, 18 `*V1_1` object types). They do **not** rewrite
`contrib/modelnet/hcp-sdk` or the frozen 34 HCP/1 operations.

The TypeScript client exposes all 50 additive operations with generated schema
types. The Python client invokes the same catalogue by operation ID (and binds
the same identifiers as methods). Both require an authentication callback bound
to the exact method/URL and a schema validator. Neither installs an OAuth
server, holds signing keys, retries financial effects automatically, or
exposes a `/rpc` passthrough.

`automatic_spend_atoms` stays **0**.

## Origin

Default origin is an independently enrolled **HTTPS** host (no userinfo, path,
query, or fragment). Loopback **http** is REGTEST lab only and requires an
explicit flag — the client does not silently accept arbitrary `http://`:

```python
CognitiveReserveClient("https://exchange.example", auth_headers, validate)
CognitiveReserveClient(
    "http://127.0.0.1:18780",
    auth_headers,
    validate,
    lab_origin="http://127.0.0.1",
)
```

```ts
new CognitiveReserveClient({ origin: "https://exchange.example", authHeaders, validate });
new CognitiveReserveClient({
  origin: "http://127.0.0.1:18780",
  labOrigin: "http://127.0.0.1",
  authHeaders,
  validate,
});
```

Use your established IDP and the enrolled provider origin. Supply a
duplicate-aware native canonical verifier for signed HCP content; ordinary HTTP
JSON parsing is not signed-canonical verification. Validate structural responses,
then verify application signatures and exact authority as required. A schema
pass is not financial approval.

## HTTP 202 is UNKNOWN

HTTP **202** means accepted asynchronous work / UNKNOWN — **not** settlement.
The client returns the 202 body (or `{status: 202, unknown: true}`) and **does
not auto-submit**, authorize, execute, or cancel as a follow-up. A request
timeout leaves business state unresolved (`UNKNOWN`). Query the existing stable
operation; never generate a new ID to retry an uncertain spend.

## body_id

```text
body_id = SHA384( UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 ||
                  LE64(len(canonical_body)) || canonical_body )
```

Applies to all 18 V1_1 types. `canonical_body` is UTF-8 compact JSON with
lexicographically sorted object keys.

```bash
python3 -m unittest -v python/test_body_id.py
node --test typescript/src/body_id.test.ts
```
