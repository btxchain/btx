# Extra High review R4 — privacy

Tree: `/home/administrator/btx-0.34.7-private`  
Method: implementation vs package spec. Production `btxd` untouched.

## Verdict

Export and instruction bodies do not embed `access_token` / prompts in the native lab. CSV cells are formula-prefixed. Chunk GET is authenticated (no public bearer URL). Daemon now emits `Cache-Control: no-store` by default. Package bytes still cannot enroll a custodian.

Remaining: GET/list maps are process-global (R1-02); Playwright browser redaction is HONEST_NOT_RUN.

## Findings

### R4-01 NOTE — export redaction is lab-complete, not a full mapping policy

**File:** `hcp_crl12_engine.inc.cpp` export POST.  
Native `cr12_sdk_02` / `cr12_sdk_07` assert no `access_token` in export JSON. CSV uses `Crl12CsvSafe`. Not a live multi-tenant export lab.

### R4-02 NOTE — Cache-Control now on the daemon path

**File:** `RunHcpDaemon` in `hcp_engine.cpp`; SignedObj sets `no-store`.  
Process-tier header check is not in `feature_modelnet_cr12.py` (MAJOR→NOTE after this round).

### R4-03 HONEST_NOT_RUN — browser accessibility / live portal

Playwright is not installed. Static a11y unittest PASS. See `audit/crl12-r8-ux.md`.
