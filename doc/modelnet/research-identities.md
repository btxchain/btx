# Research identities

Normative: root addendum §7 (D06). Qt identity UI is **out of scope**.

Model-plane identities are **ML-DSA-44** keys (libbitcoinpqc). They are
**not** wallet spending keys and MUST NOT be reused as such (v1.1 D06).

| Identity | Role |
|---|---|
| TLS / service key | PQ1 CertificateVerify. Pin after TOFU; a record does not cure a classical channel. |
| Research identity | Optional cold key for signed collections, grants, and receipts. |
| Device delegation | Scoped, revocable; never a spending key. |

No identity signature proves a person, a distinct operator, honest
behavior, model safety, or physical replica independence.

A public/free guest identity is cryptographically authenticated but not
socially trusted. Opening it does not create a monetary wallet.

This tree generates helper TLS material with `mldsa44`. Peer-certificate
**pinning** beyond “accept a well-formed ML-DSA peer” is still a gap;
capabilities must not claim a pin store that does not exist.
