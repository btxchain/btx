# Strict PQ1 model transport

New model-subsystem security uses **strict post-quantum** cryptography.
Monetary BTX (0.34.6) is unchanged: it is not “fully PQ” because the model
plane is.

## Required for native model TLS

- TLS 1.3 only
- Pure **ML-KEM-768** (never `X25519`, `X25519MLKEM768`, `SecP256r1MLKEM768`)
- **ML-DSA-44** certificates (`mldsa44`)
- Ciphersuite `TLS_AES_256_GCM_SHA384`
- No 0-RTT, no session tickets, no resumption
- Fail closed: if PQ1 cannot be configured, `btx-modeld` exits and
  monetary `btxd` continues

Model identities are ML-DSA-44 keys via libbitcoinpqc. They are **not**
wallet keys.

Artifact encryption at rest uses XChaCha20-Poly1305 (IETF, 24-byte nonce)
with domain-separated SHA-384 and HKDF-SHA384.

## OpenSSL

Need OpenSSL **3.5+** with `MLKEM768` and `mldsa44`. OpenSSL 3.0.x cannot
negotiate PQ1. A helper may be launched with a bundled 3.5 `libssl` /
`libcrypto` via `LD_LIBRARY_PATH` and `BTX_OPENSSL` (see
`contrib/modelnet/run-modeld.sh`). Spec pin 3.5.8 is a documented deviation
when the host provides 3.5.5 with the same algorithms.

The SSL_CTX pins `MLKEM768` only. Tests inspect negotiated group, version,
and ciphersuite and reject a hybrid peer.

TLS record size is bounded (512-byte send fragments) so a 4 MiB piece
cannot stall behind a WAN PMTU blackhole. TCP MSS follows the path: the
helper does **not** clamp `TCP_MAXSEG` to 800 (that packed one record per
packet and capped a real granite retrieve at ~0.2 MB/s). `SSL_write`
emits many 512-byte records into the socket buffer; it does not
PARTIAL_WRITE-step 512 bytes per syscall.

One IPv4 buyer may open `PQ1_INFLIGHT_PIECES` (8) piece sessions. The
seeder `PQ1_MAX_INBOUND_PER_NETGROUP` matches that so a single WAN IP is
not fail-closed at 2 connections. Unauth handshake flood is still 4
failures / 60s. Piece transfer timeout is 600s so a slow 4 MiB piece is
retried, not abandoned. Transient `tls io` / timeout does **not**
blacklist the only seeder; committed pieces stay on disk.
