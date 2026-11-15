# Technical references and reuse boundaries

This source is independently authored. Neuron Explorer has no identified reuse grant; none of its code, CSS, shaders or images is copied. Its README is used to identify interaction capabilities, not as proof of scientific correctness or broad model support.

- Neuron Explorer README, blob48a5e12b346883b1e3490f26f515fb4b6994c0ff: https://github.com/lyramakesmusic/neuron-explorer/blob/main/README.md
- Hugging Face chat templates and explicit formatting semantics: https://huggingface.co/docs/transformers/en/chat_templating
- Primary activation-patching research, methodological dependence: https://arxiv.org/html/2404.15255v1
- UMAP reproducibility: https://umap-learn.readthedocs.io/en/latest/reproducibility.html
- UMAP transform: https://umap-learn.readthedocs.io/en/latest/transform.html
- BTX PR245: https://github.com/btxchain/btx/pull/245

Python scientific libraries, Transformers and UMAP are external installed dependencies, not vendored code. Their licenses, package artifacts, vulnerabilities and transitive dependencies must be pinned and audited for the release. This package does not include font files, pretrained weights or external branded assets. Test-only TypeScript transformation and Playwright are not production frontend dependencies.
