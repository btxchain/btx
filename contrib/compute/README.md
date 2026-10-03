# Pay With Compute tools

These tools coordinate PWC/1. They do not spend BTX, read a wallet, or execute
a job command. Read [doc/pay-with-compute.md](../../doc/pay-with-compute.md).

| Tool | Role |
|---|---|
| `btx-compute` | Profile lookup, real harness benchmark, passport, qualification solve, quote, grant check, regtest job |
| `pwc-provider.py` | Provider-side `btx-cli` steps: issue, redeem, agree, job, accept, balance, grant |
| `reference-job-runner.py` | REGTEST ONLY deterministic commitment. Refuses `command` and any other execution field |
| `reference-access-gate.py` | `DENIED` or `ALLOWED` for one grant, via `verifycomputeaccessgrant` |
| `e2e-pay-with-compute-regtest.py` | Isolated functional scenarios. Never a production datadir |

`btx-rc-p1e-toy-v1` is **REGTEST TEST ONLY**. It cannot pay a mainnet agreement.

## Manual regtest flow

Start a regtest node with `-enablecomputetestprofiles=1` and `-modelnet=1`.

```
btx-cli -regtest getcomputeworkprofiles

challenge=$(btx-cli -regtest issuecomputequalification \
  "<32-byte-subject-hex>" "btx-rc-p1e-toy-v1" 1 300)

response=$(btx-cli -regtest solvecomputequalification "$challenge" "cpu")

btx-cli -regtest redeemcomputequalification "$challenge" "$response"
```

Then `createcomputeoffer`, `issuecomputeagreement`, and `createcomputejob`.
The worker pipes the job JSON into `reference-job-runner.py` and submits the
`output_commitment`. The provider calls `acceptcomputejobresult`,
`getcomputebalance`, and `issuecomputeaccessgrant`.

```
python3 contrib/compute/reference-access-gate.py \
  --regtest --datadir "$DATADIR" --grant grant.json \
  --subject "<subject-pubkey>" --resource "urn:btx:pwc:demo-model" --json
```

Before a valid grant the gate is `DENIED`. After settlement it is `ALLOWED`.

A production passport uses the real harness and does not invent a rate:

```
contrib/compute/btx-compute benchmark \
  --profile btx-rc-p1e-v1 \
  --backend metal \
  --episodes 100 \
  --passport-out passport.json
```

The regtest equivalent is `--profile btx-rc-p1e-toy-v1 --backend cpu`.
The harness writes `rc-report.json` in its existing schema and the passport
as a separate file.
