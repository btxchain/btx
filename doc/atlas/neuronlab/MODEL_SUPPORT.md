# Adapter and feature qualification matrix

| Surface | Source implementation | Executed here | Qualification |
|---|---|---|---|
| BTXTinyLM, GELU/SwiGLU | Custom small causal transformer, exact SafeTensors loading, all ordinary hook sites | CPU training/inference/capture/MLP interventions; numeric operator tests | Synthetic-model reference only |
| GPT2LMHeadModel | `transformer.h`, post-activation `mlp.c_proj`, attention `c_proj`, decoder output | No Transformers installation or checkpoint | SOURCE ONLY / NOT_RUN |
| LlamaForCausalLM | Dense SwiGLU block adapter | Not run | SOURCE ONLY / NOT_RUN |
| Qwen2/3ForCausalLM | Dense block adapter | Not run | SOURCE ONLY / NOT_RUN |
| Qwen3_5ForConditionalGeneration | Language-model layer adapter, MLP/residual paths | Not run | SOURCE ONLY / NOT_RUN |
| Qwen3.5 full-attention head edit | Source checks a full-attention module | Not run | SOURCE ONLY / NOT_RUN |
| Qwen3.5 linear-attention head edit | Explicit typed refusal | Structural refusal path | UNSUPPORTED; do not infer heads from attention config |
| GGUF / llama.cpp / EXL3 / vLLM / MoE | No compatible intervention kernel | Refuses rather than no-op | UNSUPPORTED |
| SAE edit | Fixed rectified-affine residual-error-preserving math and exact matrices | Numeric tensor test | No trained large SAE qualification |
| Real ML-DSA signatures | OpenSSL 3.5.5 ML-DSA-44, no fallback | Actual keygen/sign/verify/tampering tests | Local crypto-path evidence, not identity admission |
| Native BTX peer distribution | Fixed host/get/export calls and capsule checks | Local process/file transfer and plan tests only | Native network NOT_RUN |
| Tauri bridge | Source integrated with existing permission manifest | Not compiled | NOT_RUN |
| GUI | Seven tabs and perspective capture display | Offline Chromium smoke, 13 total workspaces | Browser source only, native CSP/IPC NOT_RUN |

The supported-source list is not the advertised-qualified-runtime list. Model
architecture/version mismatch, absent dependencies or unsupported layout must
produce an explicit failure. Never insert silent baseline output while reporting
that an unsupported intervention was applied.

No automatic online dependency/model fetch is performed. The reference loader
uses local files only, SafeTensors only, `trust_remote_code=False`, evaluation
mode and fp32 model loading. Config `auto_map`, executable/pickle files, symlinks,
missing weights and unknown architectures are refused.

The current function hook semantics do not implement every Lyra feature: there
is no complete live Qwen qualification, arbitrary multi-turn steering workbench,
trained semantic feature-name catalogue, automatic causal circuit tracing,
large-embedding UMAP viewer, or optimized vLLM steering backend. The added
signatures, exact artifacts, trust/activation controls and recipe-study layer
are distinct extensions, not a claim of full Lyra UI/runtime equivalence.
