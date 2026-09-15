# Canonical `btx://` resource URI

See [resource-uri-v1.md](resource-uri-v1.md) for the v1.1 rules.

Canonical form: `btx://` + 85-character Bech32m token (HRP `btx`).

Payload (5-bit groups): `[version=1, kind] || ConvertBits(SHA-384 digest, 8→5, pad=true)`.

Kinds 0–8: MODEL, ARTIFACT, COLLECTION, IDENTITY, RELEASE, POLICY_BUNDLE,
CIRCLE, ALIAS, PROVIDER.

## MUST

- Exact 85-character token after `btx://`.
- All-lower or all-upper. Mixed case is invalid.
- Bech32m checksum. One-character mutations MUST fail.
- No `/model/`, `m/`, host, query, fragment, or payment field.

## Convenience forms that decode to the canonical URI

- bare 85-char token
- `btx:` + token (no slashes)
- one trailing `/`

`btx1…` (internal Bech32 spelling) is **not** a public URI.

The HTTP bridge is a decoder, not the identity authority. Native SHA-384 is.
`btx-open` previews a URI and does nothing else.
