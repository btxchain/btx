# BTX Atlas NeuronLab — validation record

**Delivery status:** source implementation candidate. Tests below are scoped
execution evidence, not a native BTX release, complete Lyra parity, a scientific
claim about pretrained LLMs, or a formal proof of security/performance.

## Executed checks

| Check | Actual result | Scope |
|---|---|---|
| Python unit/integration tests | **69 passed; zero failures, errors or skips** | Strict codec, signatures, capsules, store, revocation, operators, actual tiny-model inference, routing, study and transfer contracts |
| Integrated JavaScript tests | **78 passed; zero failures or skips** | Prior Atlas 67 plus 11 NeuronLab cases |
| Training-recipe study | **48 actual training runs**, 24 steps each | Three seeds × two dropout settings × GELU/SwiGLU × two weight-decay settings × two optimizers; synthetic token task on small causal transformers |
| ML-DSA-44 | Actual key generation, signing, verification and tamper rejection | OpenSSL OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026); private test keys deleted, public verification material retained |
| Intervention capsule | **8,940 bytes**, signature verified | Data-only SafeTensors, exact bindings and signed manifest; no full checkpoint in delivery |
| Comparison | Real baseline/modified/sign-reversed greedy generation with selected activations | Locally trained CPU model, not a pretrained frontier/open LLM |
| Transfer | Verified in a second private-stdio worker process; remained UNTRUSTED / NOT_AUTHORIZED | One physical host, local file transfer; not native BTX peer transport |
| Browser smoke | Seven NeuronLab tabs; 13 total Atlas workspaces; 12 unmount cycles; zero page errors | Offline Chromium 144, actual recorded tiny-model measurements, Canvas2D 2.5D |
| Installer | Clean dry run, dirty/changed-source refusal, descendant branch and additive copy verified | Temporary Git fixture based on the previous Atlas overlay; fixture parent substituted only in the temporary test package |
| Schema | Recorded profile passes structural JSON Schema | Runtime semantic checks are separate; JSON Schema is not authorization |
| Package | Overlay and reviewed Python-source hashes checked; Python AST parsed | Integrity/structure only, not native compilation or dependency audit |

Original Python and JavaScript output, JUnit XML, factorial work plan/results,
signed comparison, signed capsule, process receipt, browser report/screenshots,
installer report and package integrity report are in `reports/`.

## Reproducible sample identities

- Profile ID: `81af0e5fcf889ddafc702bc056e3fa69d13aa2729681841c4677c01cb6dff7e0d9b0d40bfd6e3895ac74b91f5d53e802`
- Capsule byte SHA-384: `1678c3dddb67ed8ca3d7178fe938a77bebaa9cd6bf674b5a160d7c50a9b71e0325045674794a8fbd4837c068aa2c777b`
- Publisher research identity: `ec0439c176384801a8d2044e347d88aa6a18a88ea32ea81c784e9bdb0639c5c8013ce3b065d9c789229d25089357106e`
- Signature suite: `ML-DSA-44`

The publisher is a temporary authoring-test research identity, not an enrolled
BTX PIT identity, independent evaluator or wallet key. The public capsule is
provided for verification. Its exact tiny-model weights are not bundled; running
it requires the exact bound model. Re-running the reproducibility harness makes
fresh keys and valid new signed artifacts, not the same identity.

## Environment and experiment interpretation

Python 3.13.5, PyTorch 2.10.0+cpu, NumPy 2.3.5,
SafeTensors 0.7.0, one Linux CPU host, one configured Torch thread, no CUDA.
No Rust/Cargo or Transformers installation was available. Exact environment
metadata is in `reports/environment.json`.

The study is an executed test of the experiment machinery. It is not a finding
that dropout universally raises redundancy or polysemanticity, lowers
superposition, or improves/worsens real LLM interpretability. The task and model
are deliberately small. GELU/SwiGLU variants have approximately matched, not
identical parameter/compute counts. Optimizer recipes use different stated
learning rates. The model's implemented dropout sites share one setting. These
are explicit recipe contrasts, not a clean estimate of every isolated causal
factor or a transfer result to modern pretrained LLMs.

Selectivity, activation-rank and held-out task metrics are labelled as their
actual measurements. They are not renamed as universal monosemanticity or
superposition scores. Config values remain distinct from historical training
evidence. Unknown training history stays unknown.

## Browser validation limit

The environment rejected ordinary local URL navigation with
`ERR_BLOCKED_BY_ADMINISTRATOR`. That policy was not changed or bypassed. The
executed browser test loaded an offline test-only CommonJS transform of the
framework-free source and disabled Workers. This tests UI behavior, recorded
captures, editing, navigation, cleanup and browser-only execution refusal.
It does **not** test production CSP, normal-origin module loading, the real
Worker path, Tauri native IPC, native confirmations, native file selection,
WebGL2, wallet operations, or platform-specific WebViews. The supplied browser
harness also supports a normal URL for an authorized integration environment.

The screenshot is actual application code rendering a real measured **synthetic
CPU model experiment**, not a fabricated live BTX node. Only its two layers are
drawn; no extra model layers or scientific observations are invented for design.

## NOT_RUN / unavailable qualification

- Rust compilation, Cargo dependency resolution, native command/capability
  enforcement and native Mac/Windows/Linux packaging.
- Real pretrained GPT-2, Llama, Qwen2/3 or Qwen3.5 checkpoint loading/inference,
  calibration, captures, equivalence and GPU runs. Those adapters are source-only.
- Native `hostmodel` / `getmodel FREE_ONLY` / `exportmodelpath` against a running
  BTX daemon; real admitted physical peers, network interruption and recovery.
- First-class native intervention registry, PIT-authorized publisher enrollment,
  realm-encrypted capsule transfer, public revocation distribution or independent
  evaluator quorum. The delivered carrier and local trust do not implement these.
- Deployment of the optional generate adapter into a live BTX/Atlas assistant or
  arbitrary autonomous-agent harness. Installation alone enables none of these.
- Native OS sandbox/Windows ACL qualification, inherited process cleanup,
  immutable model snapshot race defense, dependency supply-chain audit, signed
  installers, native accessibility, GPU/RSS/idle/throughput benchmarks.
- Full Lyra neuron-explorer feature parity, inherited complete Qt replacement,
  physical distributed research, native model adoption, or financial settlement.
- End-to-end formal verification or behavioral-safety proof. Signature and hash
  checks authenticate bytes/claims; they do not prove that model behavior is safe.

GGUF, EXL3, vLLM, MoE and unsupported Qwen linear-attention head layouts have no
qualified intervention adapter in this delivery and must refuse, not silently
pretend to apply a setting.

## Re-run

Follow `README.md` and `AGENT_HANDOFF.md`. Preserve exact source/adapter hashes,
package/dependency versions, real checkpoint identity, task/data commitments,
failed outcomes and physical-host counts. New measured records must be generated
against the integrated commit and binaries. Do not convert NOT_RUN into PASS
because a source module, schema, signature or test fixture exists.
