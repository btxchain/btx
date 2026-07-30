# M4 Max Profile 2 ExactReplay Metal evidence

This directory records the corrected local measurement of the inherited PR95
Profile 2 datacenter episode. Under the MatMul v4.7 roadmap, this is historical
capacity/diagnostic evidence for the later proof-authoritative Epoch D. It is
not the Epoch-A ExactReplay workload and must not be used to make Profile 2 a
routine validator requirement. The branch was unpublished and consensus
activation remained disabled.
Transition authority and gate precedence follow the
[`MatMul v4.7 roadmap`](../../btx-matmul-v4.7-transition-roadmap.md).

## Configuration

- PR base: public PR95 head
  `43411dda8468236cd10b2441832511df34e94193`
- Local branch: `agent/metal-exact-replay`
- Host: Mac Studio, Apple M4 Max, 32 GPU cores, 36 GB unified memory
- Backend: exact Metal 4 MPP INT8 tensor operations
- Profile: 2
- Shape: eight rounds, 24 FFN layers, `b_seq=87,552`,
  `T_leaf=4,096`
- Consensus MACs: 2,257,022,493,917,184

The harness command was:

```sh
./build-metal/bin/matmul-v4-rc-harness \
  --production \
  --backend metal \
  --episodes 1 \
  --out <redacted-temporary-path>
```

`--production` now selects Profile 2. The explicitly named
`--base-production` option retains Profile 1 for comparison.

## Measured result

The complete eight-round episode took **443.438078 seconds**:

- Phase 1: 1.346553 seconds
- Phase 2: 418.733844 seconds
- Phase 3: 23.357623 seconds
- Peak resident memory: 18,799,600 KiB
- Working-set estimate: 18,735,955,968 bytes
- Device calls: 400
- Consensus MACs on Metal: 2,257,022,493,917,184 of
  2,257,022,493,917,184
- Resident 24-layer FFN-chain calls: 8
- Operand XOF calls on Metal: 21,928
- Merkle rounds on Metal: 8
- CPU calls and fallbacks: 0
- Episode digest:
  `cca1caa26e104ecb5972f7360679e0997e055335751b92a564a8d4c83294a698`

The run reported `full_metal_pipeline=true`: operand XOF, Phase 1, the resident
shared-weight Phase-2 FFN chain, both ExtractMX stages, Merkle leaves, and
Merkle subtree folding executed on Metal. This is a single sample, not a p99
campaign.

For comparison, the legacy Profile 1 run took 28.359847 seconds and
141,149,805,215,744 MACs. Profile 2 contains exactly `16422/1027`, or
15.990263 times, as many consensus MACs and took 15.636 times as long in these
measurements. The serialized header and block commitment remain unchanged;
the increase is computation and working memory, not blockchain bytes.

## Launch conclusion

This measured host misses a 90-second block interval by 353.438 seconds, even
with full Metal acceleration. Ideal wall-time division gives about 111 seconds
on four identical hosts, 74 seconds on six, and 55 seconds on eight before
coordination and p99 overhead. These are projections, not sharded
measurements.

Profile 2 ExactReplay therefore remains a no-go on one measured M4 Max. A
trusted multi-host row-sharding campaign, or the future succinct authority,
must pass the launch gate before activation.
