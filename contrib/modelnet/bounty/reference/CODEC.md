# Canonical record fixture codec

This is the normative proposed fixture encoding for new signed metadata envelopes. The implementation coordinator must freeze it alongside the production schemas before parallel implementation. It does not replace or alter existing model-byte IDs, HTLC hashes, PSBT serialization or monetary scripts.

Signing preimage = domain bytes (including one trailing zero byte) + decoded 32-byte network ID + canonical encoding of the complete signed body. Domain is `BTX/<record_type>/v1\0`, except `ModelSearchRecordV2`, which uses `BTX/ModelSearchRecord/v2\0`. The body contains exactly envelope_version, record_type, network_id, signer_id, public_key_hex, delegation_id and payload. Signature is detached; record ID is SHA-384 of this preimage. The network is also present in the typed body; both occurrences must correspond exactly. Strings containing hex IDs are canonical lowercase.

Type tags: 00 null; 01 false; 02 true; 03 unsigned 64-bit little-endian integer; 04 UTF-8 string prefixed by unsigned 32-bit little-endian byte length; 05 array prefixed by u32 element count then ordered encoded elements; 06 object prefixed by u32 field count then key/value encodings in ascending ASCII-key order. Keys are `[a-z][a-z0-9_]{0,63}`. No floats, negative JSON integers, arbitrary byte type, invalid UTF-8 or surrogate text. Monetary and precision-sensitive values are canonical decimal strings.

Generic ceilings: depth 16, 128 fields/object, 1024 entries/array, 8192 UTF-8 bytes/string, 256 KiB complete envelope. The named record schema and network endpoint impose tighter ceilings and MUST also be enforced. No truncation is permitted. Parse JSON with duplicate-key rejection, validate the complete named payload schema and semantic invariants, then verify the actual BTX ML-DSA signature and issuer/delegation. Only then mutate state. A digest comparison alone is NOT signature verification.

`bounty_reference.py` and golden-vectors.json support cross-language byte equality. The compact vector payloads exercise the codec and deliberately are not complete BountyTerms. Placeholder key bytes are not a public-key validation test. Production native tests must create real keys with BTX crypto and verify signatures plus every single-field mutation.

Run local reference examples:

    python reference/make_vectors.py
    python -m unittest discover -s reference -p 'test_*.py' -v

No script here sends network traffic, spends money, runs a model or certifies the BTX implementation.
