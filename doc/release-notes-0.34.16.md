0.34.16
=======

This tag packages the current review branches as a node release. The 0.35
line stays open for ModelNet work that is not in these branches yet.

Included
--------

- `btx-035/swarm` through `d522af52`, including the wallet, Windows, jail,
  and ML-KEM review fixes.
- `btx-035/atlas-native` through `afe27a2b`, the desktop candidate.
- `btx-035/model-security-v2` through `6fd4564e`, the local security guard.

Not included
------------

Validation, fork choice, issuance, script rules, MatMul acceptance, and the
signer set are unchanged. The height-100 candidate and the `legacy_lt_*`
results are not in this tag. `automatic_spend_atoms` stays `"0"`. Qt stays.

Local model servers
-------------------

This node does not embed llama.cpp or Ollama, and it has no quantize RPC.
A GGUF tensor whose declared size runs past the file, overflows, or overlaps
the next tensor is rejected before it is accepted. Generation runs only when
the operator points `BTX_LLAMA_CLI` or `BTX_MODEL_GENERATE` at a local
program. `-modelbind` is the PQ1 peer port, not an unauthenticated upload or
inference API. Do not publish a separate llama.cpp or Ollama server from
this host without authentication in front of it.
