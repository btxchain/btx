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
| `granite_*` | Optional large-fixture scripts; not a usefulness claim |
| `validate-doc-examples.sh` | DOC-01/02/04: run documented CLIs; no CSV PASS |
| `dependency-lock.md` | DOC-02 OpenSSL/GCC/CUDA pins |
| `e2e-resolve-8-4.sh` | RESOLVE-03/04/07 loopback independent router + 8/4 RTT |
| `e2e-nat-congested.sh` | RECIP-07/08/10 delayed proxy + STORE-01 resume |

```bash
cd contrib/modelnet/reference
python3 -m unittest -v test_v11
python3 check_schemas.py   # needs jsonschema
python3 ../two_helper_retrieve.py /path/to/build/bin
```

`run-modeld.sh` sets `LD_LIBRARY_PATH` and `BTX_OPENSSL` when `../lib`
contains OpenSSL 3.5. Use it on hosts whose system OpenSSL is 3.0.x.

Do not commit operator hostnames, public IPs, or API keys here.
