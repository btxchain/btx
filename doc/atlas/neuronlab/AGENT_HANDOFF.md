# Integration handoff — BTX Atlas NeuronLab

## Required starting point

Use the clean, committed descendant of PR #245 containing the prior independent
Atlas source. The pinned BTX ancestor is
`18ea826ee3d82edf65a274c00316bd118ed731d2`; the prior ZIP's SHA-256 and the exact
five expected Atlas source hashes are in BASELINE.json. The add-on installer
refuses changed originals. Resolve conflicts by reviewing both trees; do not
blindly disable the checks or overwrite another worker's changes.

Suggested new branch: `btx-035/atlas-neuronlab`.
PR base: the already-integrated Atlas branch, not a branch that omits that work.
No GitHub write has been performed by this delivery.

## Work already implemented and executed

The source contains the scientific worker, fixed numeric operations, real
ML-DSA-44 capsules, local trust/activation fences, exact binding, runtime module
fingerprints, direction extraction and receipts, source adapters, study/evaluation
harness, context router, existing-generate-contract adapter, native bridge and
new GUI workspace. See VALIDATION.md and raw reports for checks actually run.

Do not replace working numeric tests with stubs, synthetic success booleans,
invented model activations or guessed global swarm observations.

## Integration order

1. Apply the checked overlay on its new branch. Inspect the five modified original
   files: app navigation, web CSS inclusion, native module/handler registration,
   Tauri command manifest and main-window permissions.
2. Run Python and integrated JS tests. Rebuild `code-manifest.json` with the supplied
   tool whenever reviewed scientific source changes. Changed code can alter the
   execution fingerprint and deliberately invalidate old model/profile bindings.
3. Resolve and audit the inherited Cargo dependency graph. Compile/format/test the
   Rust bridge and fix any API/compiler issues. No native compilation took place
   in the authoring environment. Commit Cargo.lock only after this review.
4. Exercise native file selection, source review, concurrency, cancel, timeout,
   strict IPC, research key initialization, trust and native confirmations on
   Linux/macOS/Windows. Try remote and nested WebViews and generated panels.
5. Test actual local GPT-2, Llama and Qwen variants separately. Source adapters are
   not qualification. Compare trusted baseline output to the instrumented
   no-op path, actual edited activations, phase/padding semantics, absence of
   weight changes, precise tokenizer/config binding and final revocation fences.
   Keep unsupported linear attention, MoE/GGUF/EXL3/vLLM explicitly unsupported.
6. Test real native transport on disposable regtest nodes: host a PUBLIC signed
   capsule as data; acquire FREE_ONLY from another participant; wait for native
   completion; export its verified checkout; reject the wrong expected profile;
   import untrusted with NO activation; explicitly trust and run on an exact
   model; revoke while running and reject result release. Count physical hosts
   honestly. A local process test is not this acceptance test.
7. Decide whether to add a first-class native intervention-artifact record. The
   supplied SafeTensors carrier is an explicit-URI compatibility path with search
   publication disabled, not a completed global registry. Preserve catalog/model
   distinctions and observer semantics. Do not modify consensus or introduce a
   second swarm scheduler.
8. Keep realm/private publishing disabled on the public carrier. Implement and
   independently test native realm encryption/identity delegation before claiming
   that capability. Research keys are not automatically PIT or wallet identities.
9. Install the optional generate adapter only for an actually qualified local
   architecture and under an explicit operator environment change. Verify the
   existing Atlas assistant still has no authority to approve settings, sign
   transactions, broaden tool privileges or route private prompts to peers.
10. Audit dependencies, OS isolation/ACLs, process descendants, source races,
    immutable model snapshots and GPU resource pressure. Benchmark actual
    prefill/decode overhead, selected captures, model hashing/load time and native
    renderer memory on specified hardware, not only the CPU toy experiment.
11. Preserve inherited Atlas wallet and full Qt parity gates. This add-on does
    not make the unqualified baseline native app production-ready and does not
    authorize deleting Qt or announcing qualified distributed model evolution.

## Scientific acceptance

Require exact dataset/split commitments, declared hypotheses/trials, control
profiles, negative results, tokenization, hook point, numerical units, training
history evidence, backend/precision and private-data scope. Do not conflate
selectivity, redundancy, polysemanticity and superposition. A signed author claim
is not independent evidence. Config defaults are not historical training records.

The 48-run validation proves that the small-model factor harness performs actual
training; it is not a conclusion about dropout in modern pretrained LLMs. Separate
optimizer learning rates and approximately matched architectures are explicitly
part of the recipes. Obtain broader evidence before making scientific claims.

## Suggested PR body

“Adds the NeuronLab Atlas workspace and signed, checkpoint-bound inference-time
intervention profiles. Implements bounded local tensor operations, private
counterfactual evidence, recipe-aware studies, trust/activation separation and a
source bridge to existing native byte transport. Exact source parent: [SHA].
Executed checks: [reports]. Native/engine/network/platform gates: [actual status].
No consensus, wallet or automatic-spend change. No claim of full Lyra parity,
independent physical-swarm qualification or formal behavioral safety.”
