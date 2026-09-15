# Web / browser bridge boundary

Normative: root addendum §10 (D09). Native-only remains a valid deployment
(omit the bridge). Public DNS 42/43 and system WebPKI verification are
**implemented** in this tree; they are not an operator-kit sketch.

v1.1 D09: native model transport remains **strict PQ1**. A browser bridge
is a **separately deployed** compatibility service. Native helper
(`btx-modeld`) never terminates classical TLS.

| Edge | Allowed | Claim |
|---|---|---|
| Native `btx-modeld` | PQ1 only (ML-KEM-768, ML-DSA-44, AES-256-GCM-SHA384) | End-to-end PQ for that hop |
| Browser HTTPS | Conventional HTTPS at the **external** browser edge (system WebPKI) | Explicitly **not** end-to-end PQ |
| Bridge → BTX | Still PQ1 upstream | Never a wallet proxy or payment authority |

A PQ-only deployment **omits** the bridge. D09 is not permission to restore
classical TLS inside `btx-modeld`.

## Public DNS 42/43

An 85-char Bech32m token is not a legal single DNS label (max 63).
`DnsSplit42_43` in `src/modelnet/http_bridge.cpp` splits the token into labels
of 42 and 43 characters and joins `{left}.{right}.{zone}`.

Live lookups: `contrib/modelnet/e2e-public-webpki-kit.sh` uses `getent`/`dig`
against `PUBLIC_BRIDGE_HOST` (default **`example.com`**, the IANA documented
test host). If the operator publishes the split FQDN, the kit also connects
with SNI using the system trust store.

System WebPKI TLS (not local-CA-only): `contrib/modelnet/e2e-webpki-tls.sh`
handshakes `PUBLIC_WEBPKI_HOST` (default **`example.com`**). JSON responses
carry `Content-Security-Policy: default-src 'none'` from `FillJson` and
`contrib/modelbridge`.

See [howto.md](howto.md). Native `btx-modeld` never terminates TLS at this edge.
