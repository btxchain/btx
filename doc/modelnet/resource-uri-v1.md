# Compact BTX Resource URI (v1.1)

Normative: root addendum §3 (`BTX-SPEC-0347-MODELNET-ROOT-1.1`). B0
§5 / Appendix A remain for object identity; this page does not rewrite B0.

Canonical form:

```
btx://<85-character Bech32m token>
```

HRP is `btx`. The token carries `[version=1, kind]` plus the full 48-byte
SHA-384 identifier and a Bech32m checksum. The complete URI is 91
characters. It is not a truncated hash, a DNS name, or a payment
instruction.

Kinds 0–8: `MODEL`, `ARTIFACT`, `COLLECTION`, `IDENTITY`, `RELEASE`,
`POLICY_BUNDLE`, `CIRCLE`, `ALIAS`, `PROVIDER`.

Complete synthetic MODEL example (format vector only; not a hosted
commitment):

```text
btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25
```

## MUST

- Exact 85-character token after `btx://`
- All-lower or all-upper; mixed case is invalid
- Bech32m checksum; one-character mutations MUST fail
- No `/model/`, `m/`, host, query, fragment, or payment field

## Convenience forms that decode to the canonical URI

- bare 85-character token
- `btx:` + token (no slashes)
- one trailing `/`

`btx1…` (internal Bech32 spelling) is **not** a public URI.

The HTTP bridge, if any, is a decoder — not the identity authority. Native
SHA-384 is. See also the shorter notes in [uri.md](uri.md) (same rules).
