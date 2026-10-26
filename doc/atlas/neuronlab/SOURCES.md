# Source references and evidence boundaries

Primary references inspected 26 October 2026. These are design/scientific
references, not software bundled wholesale into this add-on.

1. Víctor Mayoral-Vilches, Hugo Osuna, Aitana Cornago, *The Psychology of an AI Hacker*,
   arXiv:2610.30361v1, 21 October 2026. https://arxiv.org/abs/2610.30361
   Figure 4 / section 2 inform reversible norm-scaled residual steering; the
   paper's gains, direction labels and routing outcomes are not BTX measurements.
2. Lyra, Neuron Explorer. https://github.com/lyramakesmusic/neuron-explorer
   `explorer/runtime.py` documents post-product MLP hooks, calibrated doses,
   attention-head controls and sign-reversed comparisons. No reuse license was
   identified in the inspected repository, so its code/assets are not copied.
3. Hugging Face Transformers GPT-2 documentation.
   https://huggingface.co/docs/transformers/model_doc/gpt2
   Dropout configuration defaults are not independent checkpoint training records.
4. Elhage et al., *Toy Models of Superposition*.
   https://transformer-circuits.pub/2022/toy_model/index.html
   Sparse-feature superposition is a specific explanatory model; a neuron label
   or covariance rank is not a universal superposition measurement.
5. Nanda et al., *Diffused Redundancy in Pre-trained Representations*.
   https://arxiv.org/abs/2306.00183
   Training objective/data and downstream task can matter to redundancy. The
   vision/representation results are not a universal modern-language-model law.
6. BTX PR #245, inspected head `18ea826ee3d82edf65a274c00316bd118ed731d2`.
   https://github.com/btxchain/btx/pull/245
   Existing `contrib/modelnet/generate_local.py`, `doc/modelnet/generate.md`,
   `doc/modelnet/rpc.md`, and native participation documents define the integration
   contracts. No new native RPC is presumed to exist merely because it is named
   in a design document.
7. Prior Atlas source and handoff supplied in this conversation. This add-on
   preserves the framework-free client and Rust/Tauri authority architecture.

All new implementation source is independently written. Numeric reference
experiments use generated synthetic data. Third-party package licenses and the
inherited Atlas dependency tree remain subject to the integrating agent's pinned
license/SBOM audit. A source checksum is not a legal license opinion or a supply
chain certification.
