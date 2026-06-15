# Phase 2: v3 solver pipeline-overlap - LIVE throughput + stability sweep

Host: pc (omarchy, RTX 5090, sm_120). btx 0.32.11 (215170f2), CUDA 12.8.
Byte-exactness PROVEN in Phase 1 (serial vs overlap = identical nonces+digests);
this phase is THROUGHPUT + STABILITY only.

Metric source: getmatmulchallengeprofile ->
  service_profile.runtime_observability.solve_pipeline.batched_nonce_attempts
  (delta / elapsed = attempts/s). GPU duty = avg of nvidia-smi utilization.gpu
  sampled 1 Hz over the window. "stable" = no rejects/CUDA faults/stalls in
  `docker compose logs btx-miner` AND height advancing.

Baseline image btx-miner:local (stock, serial, async OFF, no overlap env).
Overlap image btx-miner:overlap = btx-miner:local with the Phase-1 overlap btxd
swapped over /opt/btx/bin/btxd (only btxd changes; btx-cli left stock). Default
env keeps overlap OFF, so the image is stock-equivalent until async=1.

Pre-flight: health watchdog STOPPED for the sweep (empty-block keeper left up).
Each overlap config recreates the btx-miner container (warmup ~6-8 min: waited
for getblockchaininfo ibd=false AND chain_guard reason=healthy before sampling).

DECISION RULE: winner = highest attempts/s. SWITCH to an overlap config ONLY IF
its attempts/s >= 15% above the stock baseline AND stable. Else winner = STOCK.

## Measurements

### Config 1 - BASELINE (stock btx-miner:local, serial, gpu_inputs=default)
Live running container, measured in place (NOT restarted -> genuine stock; it had
been up ~3h at steady state). async=false, prefetch=1, batch=2048, cpu_confirm=true.

  sample A: duty=63.6%  attempts/s=11375   (height advanced, chain_guard healthy)
  sample B: duty=62.7%  attempts/s=11523   (height advanced, chain_guard healthy)
  BASELINE MEAN: duty ~63.2%  attempts/s ~11449   STABLE: yes

  +15% switch threshold = 11449 * 1.15 = 13166 attempts/s.

(further configs appended as measured)

### Config 2 - overlap, async=1, prefetch=3, workers=4, gpu_inputs=1
Image btx-miner:overlap. Profile confirmed overlap ACTIVE: async_prepare_enabled=true,
prefetch_depth=3, async_prepare_worker_threads=4, batch=2048, cpu_confirm=true.
Warmup ~12 min to ibd=false + chain_guard healthy before sampling.

  sample A: duty=66.7%  attempts/s=14765   (height advanced, chain_guard healthy)
  sample B: duty=60.7%  attempts/s=13376   (chain_guard healthy; 0 blocks in the 60s
            window = normal solo variance, not a stall - height advancing across samples)
  MEAN: duty ~63.7%  attempts/s ~14071   STABLE: yes (log scan: no errors/rejects/CUDA faults)

  vs baseline 11449: +22.9%  -> CLEARS the +15% switch threshold.


### Config 3 - overlap, async=1, prefetch=3, workers=8, gpu_inputs=0
Image btx-miner:overlap. Profile confirmed overlap ACTIVE: async_prepare_enabled=true,
prefetch_depth=3, async_prepare_worker_threads=8, batch=2048. gpu_input_generation_attempts=0
(CPU-side input gen, as set by gpu_inputs=0).

  sample A (60s): duty=20.2%  attempts/s=0   (dnonce=0; batched_nonce_attempts stuck ~4096)
  sample B (90s): duty=21.7%  attempts/s=0   (dnonce=0; 0 solver blocks in window)
  STABLE: no CUDA faults, BUT the SOLVER IS STARVED.

  DIAGNOSIS: with gpu_inputs=0 the 9800X3D cannot generate MatMul inputs fast enough to
  keep even ONE GPU digest batch in flight, and the overlap does NOT rescue it (the prepare
  worker pool is the bottleneck, not scheduling). batched_nonce_attempts barely moves
  (~4096 total over minutes), GPU duty collapses to ~21%, attempts/s ~= 0. The lone block
  that landed during a window came from the empty-block keeper, NOT the GPU solver. Same
  starvation the pool gpu_inputs=0 default showed on this card. HARD LOSS vs baseline
  (11449). "CPU input gen hidden behind GPU digest" does not hold on a 5090 + 9800X3D:
  the CPU side is too slow to hide.

### Config 4 - overlap, gpu_inputs=0, prefetch=2, workers=4
SKIPPED per the decision rule (only run if Config 3 beats baseline). Config 3 was ~0
attempts/s (starved), so a lighter gpu_inputs=0 variant cannot help: the bottleneck is
CPU input-generation throughput, which fewer prepare workers / shallower prefetch only
worsens. The gpu_inputs=0 path is non-viable on this hardware.

## DECISION

Winner = Config 2 (overlap, gpu_inputs=1, async=1, prefetch=3, workers=4).
  attempts/s ~14071 vs baseline ~11449 = +22.9%  ->  CLEARS the +15% switch threshold,
  and STABLE (no rejects / CUDA faults / stalls; height advancing).
Config 3 (gpu_inputs=0) starved (~0 attempts/s) and Config 4 skipped.

ACTION: SWITCH solo to the overlap build with Config 2 env. gpu_inputs MUST stay 1 on
this box (the 5090 needs on-GPU input generation; the overlap then hides the per-window
CPU prepare + next GPU prehash scan behind the in-flight digest, lifting duty and
attempts/s ~23% over serial).


## DEPLOYMENT + STABILITY RE-CHECK (deployed winner = Config 2)

Deployed via the auto-loaded docker-compose.override.yml (image btx-miner:overlap +
async=1/prefetch=3/workers=4/gpu_inputs=1), so plain `docker compose up -d btx-miner`
(what mining-watchdog.sh and `make solo` run) reproduces it with NO extra flags. The
redundant docker-compose.phase2.yml sweep file was removed. Post-deploy the node
restarted, caught up the ~40 blocks it missed during the recreate (local 131094 ->
131136 == peer_median), rebuilt peer topology, and reached chain_guard healthy.

Stability watch (~4 min, chain_guard healthy throughout, overlap async=true):
  sample 1 (60s): duty=70.9%  attempts/s=15632   height advancing
  sample 2 (60s): duty=57.6%  attempts/s=14269   height +2 (solo blocks won)
  sample 3 (60s): duty=64.5%  attempts/s=13569   height +2 (solo blocks won)
  MEAN: attempts/s ~14490  (all 3 > the 13166 threshold; ~+27% over baseline 11449)
  Height advanced 131137 -> 131141 (+4 blocks via the GPU solver) over the window.
  Log scan: 0 PoW / consensus / CUDA / reject / fork / OOM errors (the lone "fault"
  match is the benign device_prepared_inputs_default: false config echo).
  STABLE: YES. No revert needed.

## FINAL RUNNING STATE
  image: btx-miner:overlap   (btx-miner:local preserved as rollback, untouched)
  env:   BTX_MATMUL_PIPELINE_ASYNC=1  BTX_MATMUL_PREPARE_PREFETCH_DEPTH=3
         BTX_MATMUL_PREPARE_WORKERS=4  BTX_MATMUL_GPU_INPUTS=1
         (BTX_MATMUL_BACKEND=cuda, BTX_MATMUL_SOLVER_THREADS=12, BTX_MINING_ENABLED=1)
  overlap ACTIVE (async_prepare_enabled=true), chain_guard healthy, height advancing,
  solve attempts/s ~14.5k (vs stock serial ~11.4k).
  watchdog: relaunched (auto-loads the override -> restarts preserve the overlap config).
  empty-block keeper: still running.

ROLLBACK: edit docker-compose.override.yml -> image: btx-miner:local and set
BTX_MATMUL_PIPELINE_ASYNC: "0" (or drop the 4 BTX_MATMUL_* lines), then
`docker compose up -d btx-miner`. btx-miner:local image is unchanged.
