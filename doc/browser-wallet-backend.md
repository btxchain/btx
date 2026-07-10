# Browser wallet backend contract

The BTX browser wallet is a separate application that derives keys and signs
P2MR transactions locally. `btx-node` is its consensus and relay backend; it is
not a public browser API and must not receive node credentials from browser
code.

## Required transaction path

A constrained same-origin gateway or explorer service may expose an anonymous,
rate-limited broadcast endpoint. That service must:

1. accept one raw-transaction hex string with a strict request-size limit;
2. reject malformed JSON, non-hex, oversized, and duplicate requests before
   contacting the node;
3. call `testmempoolaccept` first and return its reject reason without leaking
   RPC credentials or internal host details;
4. call `sendrawtransaction` only for an accepted transaction;
5. cap upstream concurrency and per-origin/IP request rate;
6. permit only the deployed website origin through CORS; and
7. log transaction IDs and aggregate outcomes, never wallet seeds, descriptors,
   files, document contents, or node credentials.

Do not bind JSON-RPC to a public interface for this purpose. Keep RPC on a
private or loopback address and place the gateway in a separate least-privilege
process.

## Browser-produced P2MR transaction profile

The current website spends the default receive address through its ML-DSA-44
leaf. A normal witness is:

`[2420-byte signature, 1316-byte ML-DSA leaf script, 33-byte control block]`

The transaction uses version 2, sequence `0xfffffffd`, an anti-fee-sniping
locktime based on the current tip, and P2MR outputs. BTX has no witness discount,
so fee policy must use the complete serialized size. The browser must validate
the explorer-provided outpoint script and amount against its locally derived
address before signing.

Node-side release gates for this profile are:

- `rpc_pq_wallet.py`
- `rpc_rawtransaction.py`
- `feature_p2mr_end_to_end.py`
- `p2mr_end_to_end.py`
- `testmempoolaccept` and `sendrawtransaction` negative cases

The website additionally owns deterministic builder/WASM vectors and mocked
gateway tests. A green node test suite does not replace browser tests, and a
green browser suite does not replace node policy/consensus tests.

## Detached post-quantum document signatures

The website's document/text signing envelope is application-domain data. It is
not a transaction, BIP322 message, consensus object, or `btx-util
verifyupdatesig` payload. The node does not need document contents and must not
receive them.

Verification establishes that an ML-DSA signature is valid for the signed
claims and that the ML-DSA public key is committed by the claimed P2MR address.
It does not establish legal identity, a trusted timestamp, current balance,
unspent funds, or encryption. Public release claims must preserve this boundary
until an independently specified native envelope verifier is added.
