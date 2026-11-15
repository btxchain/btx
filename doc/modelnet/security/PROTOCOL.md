# Security-v2 wire and record contract

## Canonical signatures

The envelope is `BTX/SecurityEnvelope/v1`, with exactly `schema`, `kind`, `body`,
and `signatures`. Signatures use BTX's actual ML-DSA-44 implementation (public key
1312 bytes, secret key 2560 bytes, signature 2420 bytes). Keys and signatures are
lowercase hex. Secret keys are private files, never argv or inherited environment.

Canonical encoding is **BTX canonical integer-JSON v1, not RFC 8785/JCS**. Object
keys are sorted; duplicate keys, floats, negative zero, malformed UTF-8 and
excessive nesting/sizes are rejected. Signed bytes are constructed by `SigningMessage`
in `common.cpp`: domain `BTX/SecurityRecord/CanonicalJsonInteger/v1`, kind and
canonical body, each with an eight-byte little-endian length prefix. The
signature implementation uses no prehash variant. Read that function rather
than assuming signing is over pretty-printed JSON.

Object IDs are a SHA-384 domain-separated hash of kind/body, excluding the
signature list so independent endorsements have one identity. See `DomainHash`
for exact length-prefix encoding. A signature never imports its own trust root.
`schemas/security-records.schema.json` documents shapes; C++ additionally checks
signature authority, hash closure, freshness and local effects.

## Existing guard-pipe extension

Legacy `PING`/permit messages remain compatible. Legacy consumption continues
to say `NOT_DISPATCHED`. Typed security-v2 messages are separate:

```
SEC2 BEGIN <16-byte nonce hex> <canonical request byte length>
SEC2 DATA <same nonce> <offset> <up-to-1536-byte hex fragment>
SEC2 COMMIT <same nonce>
SEC2 READ <same nonce> <response offset>
```

The maximum assembled record is 1 MiB; maximum line is 4096 bytes; assembly has
a ten-second deadline. Out-of-order, duplicate, oversized or incomplete framing
is refused. The supervisor holds one lock for the entire exchange. Async effects
return a job id; `poll` yields metadata, while `take` releases output once after
a current authorization check. No public TCP transport is added.

## Owner RPC operations

`status`, `install-policy`, `import`, `get`, `admit`, `follow`, `observe`,
`activate`, `prepare`, `execute`, `pause`, `resume`, `poll`, `take`, `publish`,
`resident-import`, `evaluate`, `canary`, and `stage` are implemented. Consult
`Service::Handle` and `Service::Impl::Perform` for exact required keys. Unknown
fields/verbs fail closed. `execute`, `resident-import`, `evaluate`, `canary`,
and `stage` are asynchronous. No wallet, spend, generic shell, arbitrary network
or dynamic plugin operation exists in this interface.

An action context has realm, composition, runtime, tool_schema and session.
A typed request is one of:

```json
{"tool":"read","path":"src/example.cpp"}
{"tool":"hash","path":"src/example.cpp"}
{"tool":"write-new","path":"result.txt","payload_hex":"6869"}
{"tool":"run-static","package":"<96-hex locally approved package id>","payload_hex":""}
```

The grant separately pins all permissible paths, packages, runtime/tool identity,
workspace handle, session, limits and expiry. Passing a path in a request never
creates authorization for it.

## Peer evidence protocol

`POST /btx-model/2/security/evidence` carries a signed `peer` envelope on an
already authenticated native PQ1 connection. Request and response bind sender,
recipient, realm, policy epoch, request ID, fresh nonce and short expiry. The
actual session pin is used; a body/header cannot invent it. Request rate,
nonces, outstanding requests, inventories, wanted IDs and total bytes are
bounded. There is no peer-to-owner-RPC passthrough.

An inventory contains public evidence IDs, not secrets or prompts. The follow-up
requests retrieve signed evidence and recursively queue referenced evidence.
Unknown/private resources share one `not_available` behavior. Each received
record is independently signature/role/realm checked. Received evidence is not
automatically given local publication or execution authority.

The peer module can converge evidence between enrolled nodes; native PQ1 socket
execution of these new hooks remains to be run. This package does not add a new
peer model-weight transfer protocol, distributed training transport or HTLC mesh.
