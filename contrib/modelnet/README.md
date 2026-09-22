# contrib/modelnet — reference codecs, schemas, helper smokes

A BTX node already has compute. This directory is **not** an inference
service. It holds:

| Path | Role |
|---|---|
| `reference/` | v1.1 URI/record codecs (57 unittest methods). Not production TLS. |
| `schemas/` | JSON Schema for v1.1 record bodies |
| `failfast.py` | Shared wait/poll: abort if helper died or `getmodeljob` failed |
| `e2e-all.sh` | Fail-fast local process suite (units + loopback e2e) |
| `e2e-regtest-two-host.sh` | Isolated `btxd -regtest` + helpers on two hosts (`SEEDER_BTXD` / `FETCHER_BTXD` / `SEEDER_MODELD` / `FETCHER_MODELD` / `SEEDER_DIR` / `FETCHER_DIR`) |
| `e2e-regtest-three-host.sh` | Same plus `THIRD_HOST` client via tunnel; demand-seed; `THIRD_PROD_PIDS` if set |
| `e2e-public-webpki-kit.sh` | Live public DNS 42/43 (getent/dig) + system WebPKI TLS |
| `e2e-two-node-demand.sh` | WAN retrieve; demand-seed default (no seedmodel) |
| `run-modeld.sh` | Launch helper with bundled OpenSSL 3.5 when present |
| `generate_local.py` | Operator `BTX_MODEL_GENERATE` adapter: local one-shot GGUF (`BTX_LLAMA_CLI`) or allowlisted SafeTensors (`transformers`, `local_files_only`, `trust_remote_code=False`). Missing deps → `ok=false` NOT_RUN. Not a network server. |
| `granite_*` | Real `ibm-granite/granite-4.0-h-tiny` loopback scripts (URI `btx://pqc0whmrlv2emtc8eknxja6l6ffdj5mta0nj9msfsdkrz6qg0de448gm0a3kcctd92p9ekje2c97wd5glyrdl`; 13,888,336,427 bytes, 13 files, 3,322 pieces). SafeTensors hybrid MoE/Mamba. `importmodel` demand-seeds without `seedmodel` (`family=granite`, `STRUCTURE_VERIFIED`, 193 tensors on shard1, `execution_profile` stays **0** / unqualified; not dense-decoder-v1). llama.cpp cannot open that checkout without GGUF conversion. Not a usefulness or safety claim. `getmodel` accepts a `.btx` share file or a `btx://` URI. `btx-model host foo.btx` is `getmodel FREE_ONLY` (retrieves the share); RPC `hostmodel` of a share_card reports `reason=share_card` / `imported=false` and nests that retrieve. `exportmodelpath` rebuilds original files under `checkout/<artifact>/` (`path` / `usable_runtime_root`) and hardlinks from `source_path` when SHA-384 still matches. `loadmodel` with `BTX_MODEL_CUDA_LOADER` pointing at `cuda_safetensors_load` keeps tensors resident (`--hold --smoke`): `device_loaded`, `runtime_started`, `weights_resident`, `smoke_passed`. `inference=false`, `remote_inference=false`. `unloadmodel` SIGTERMs the loader child only. Optional `BTX_MODEL_INFER_CMD` is an operator generate hook, not a fake PASS. `generatemodel` is host-profile local generate (`BTX_MODEL_GENERATE` / `BTX_LLAMA_CLI`); granite hybrid is allowlisted SafeTensors, not GGUF. CUDA smoke is not generate. `granite_user_scenarios.py` is the .btx + URI + checkout (+ optional CUDA) path. `granite_host_roundtrip.py` still polls `getmodeljob` and requires 3322 pieces / 13888336427 bytes. `two_helper_retrieve.py` and `e2e-local-helper.sh` are TinySafeTensors / 10-byte stub smokes. Hugging Face `live_wan`: Range on tiny files may return 200 with `Content-Length` equal to the requested extent at offset 0; weight CDNs still return 206. |
| `validate-doc-examples.sh` | DOC-01/02/04: run documented CLIs; no CSV PASS |
| `dependency-lock.md` | DOC-02 OpenSSL/GCC/CUDA pins |
| `e2e-resolve-8-4.sh` | RESOLVE-03/04/07 loopback independent router + 8/4 RTT |
| `e2e-nat-congested.sh` | RECIP-07/08/10 delayed proxy + STORE-01 resume |
| `hcp-sdk/` | HCP/1 typed clients (Python `btx_hcp.py`, TypeScript). Not a wallet. `automatic_spend_atoms=0`. HTTP 202 is not settlement. |
| `hcp-portal/` | Static catalogue/pairing shell (`index.html`). No custody keys, no token-in-URI. |
| `hcp-gateway/` | Design YAML only (`config.example.yaml`). Native gateway binary is `btx-hcpd`, not this kit. |
| `hcp-reference/` | Offline contract/simulator kit. SIMULATION_ONLY. Not OAuth, ML-DSA, custody, or a live CEX. |
| `crf-sdk/` | Cognitive Reserve v1.1 typed clients (additive to HCP/1; 50 ops). Not a second ledger. |
| `crf-portal/` | Reserve/committee/holdings portal shell. Family view is not debit authority. |
| `crf-reference/` | Offline capacity/TCO/DAG/quorum reference. Not an exchange ledger. |

```bash
cd contrib/modelnet/reference
python3 -m unittest -v test_v11
python3 check_schemas.py   # needs jsonschema
python3 ../two_helper_retrieve.py /path/to/build/bin
```

**0.34.9 host / load / checkout / generate.** `scanmodelwatch` on a dropped `.btx`
still opens the card and starts FREE_ONLY `getmodel` (quota applies to
the model, not the card bytes). `ensurebtxcapability` remains the lab
CPU fixture unless the request names a complete catalog replica and a
non-CPU runtime (`safetensors-cuda` / CUDA backend +
`BTX_MODEL_CUDA_LOADER`); report `payload_source` honestly.
`LoadTrustedRuntime` CUDA is `LIVE_RUNTIME_NOT_RUN` unless that env is
set and the payload/checkout is SafeTensors. JIT-RUN-02 still
fail-closes without it. `generatemodel` matches GGUF+`BTX_LLAMA_CLI` or
allowlisted SafeTensors+`BTX_MODEL_GENERATE`; pickle and unknown
architectures fail closed. CUDA smoke is not generate.
`automatic_spend_atoms=0`.

`run-modeld.sh` sets `LD_LIBRARY_PATH` and `BTX_OPENSSL` when `../lib`
contains OpenSSL 3.5. Use it on hosts whose system OpenSSL is 3.0.x.

Do not commit operator hostnames, public IPs, or API keys here.
