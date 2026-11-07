# Security and research-assurance boundaries

## Trust model

The local operator and explicitly installed application/scientific code are
trusted. Models, peer advertisements, capsules, scientific claims, external
receipts and renderer-provided arguments are untrusted until the relevant
specific check. A cryptographic signature establishes authorship/integrity of
bytes, not semantic correctness, behavioral safety, independent evaluation,
royalty rights, a financial claim, or permission to run on another machine.

## Implemented mechanisms

1. Data-only numeric operators, strict canonical signed JSON, finite F32 tensors,
   type/shape/size bounds, offsets checked before materialization, no pickle/eval.
2. ML-DSA-44 detached signatures, explicit domains for profiles/evidence, exact
   tensor digests, strict model/config/tokenizer/adapter fingerprint matching.
3. No activation on import; local trust separate from signature validity;
   expected-generation activation; revocation and final-result fences.
4. Native review for writes and computation; native-selected file paths; fixed
   reconstructed BTX byte-transfer calls rather than arbitrary RPC forwarding.
5. Private stdin/stdout worker; no listener, wallet key, RPC cookie, cloud provider,
   arbitrary subprocess request, model-authored execution code, or peer scheduler.
6. Single model-request hook owner, unconditional cleanup, private KV caches,
   bounded capture/read/response budgets and cancellation. GUI failure does not
   terminate the monetary daemon.
7. Owner-only local files on POSIX, bounded atomic writes, SQLite transactions,
   source/interpreter hashes and local evidence/event records.

## Explicitly not proved or qualified

- Rust was not compiled and native WebView commands/dialogs/permissions were not
  executed. Textual structure checks are not compiler or IPC security tests.
- Private stdio is not an OS sandbox. Scientific libraries are native code, and
  a malicious process acting as the same OS user remains outside this boundary.
  Linux namespaces/seccomp, macOS sandboxing, Windows restricted tokens/Job
  Objects and restrictive file ACLs need a reviewed native implementation/profile.
- Hashes do not replace signed software distribution, dependency audit, package
  provenance or checking every transitive library. The source manifest is locally
  reviewed, not an independent vendor certificate. OpenSSL/Python/PyTorch and
  tokenizer libraries are trusted installed dependencies.
- File hashing is not a perfect defense against an attacker racing same-user
  files. Qualify immutable verified checkpoint snapshots before production.
- The native timeout kills the immediate scientific worker. Descendant/process
  containment and adversarial pipe shutdown need native platform testing.
- Local evidence and signature keys are not automatically admitted PIT identities.
  An operator-assigned trust-domain label does not establish real independence.
- Local journal hash chains are not externally anchored and do not prevent an
  authorized filesystem owner from replacing the entire store.
- Data-only steering can still substantially worsen behavior, change task choices,
  or embed prompt-specific harmful effects. The numerical delta cap is not a
  behavioral safety proof. Test benign regressions, canaries, adversarial prompts,
  holdouts, source trust and host capabilities independently.
- Numerical values/activations/outputs may reveal private prompts or data. Receipts
  remain local by default. Public publication must be an explicit owner choice.
  No cryptographic privacy claim is made for raw activations or vectors.
- Live execution can be expensive. The reference loader is FP32 and rehashes the
  model. No production RSS, GPU memory, frame-time or formal WCET claim is made.

## Required adversarial integration tests

Try capsule byte/metadata/tensor tampering, malformed offsets, huge dimensions,
NaN/Inf, duplicate JSON keys, nested payload bombs, Unicode ambiguity, cross-model
replay, new tokenizer/config, changed adapter modules, injected source paths,
unknown operators, stale activation generations, trust revocation during decode,
wrong capsule returned for a native resource, unknown delivery outcome, session
cancellation, source changes after runner configuration, generated UI calling
commands, and remote/nested WebView IPC. Preserve failed outcomes in the report.

Before enabling this for an autonomous agent, confirm its filesystem, tools,
network and spending privileges remain independently mediated. A steering profile
must never be able to increase the agent's host authority, alter wallet approval,
change monetary consensus, or approve its own activation.
