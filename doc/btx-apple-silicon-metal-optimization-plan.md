# Comprehensive Apple Silicon Mining Optimization and BTX Unit Migration Plan

## Current Architecture Analysis

### Mining Pipeline (per nonce attempt at mainnet n=512, b=16, r=8)

```
CPU: DeriveSigma ──> noise::Generate ──> Low-rank products ──> A+E, B+F
         2 SHA256      16,384 SHA256      2x O(n²r) matmul     O(n²) add
         ~1 µs            ~0.8 ms            ~2 ms              ~0.2 ms
                                │
         ┌──────────────────────┘
         v
GPU: build_perturbed ──> build_prefix ──> compress_prefix ──> CPU: SHA256
      O(n²r)               O(n³)           O(n³/b)            128KB hash
      ~0.05 ms             ~1-5 ms          ~0.1 ms            ~0.05 ms
```

**Total per nonce: ~2-8 ms (Metal) | ~200-500 ms (CPU-only)**

### Critical Constraint: `simdgroup_matrix` Does NOT Support uint32

The MatMul PoW operates in GF(2^31-1) with uint32 elements. Metal's hardware-accelerated
`simdgroup_matrix` operations only support float/half/bfloat types. Since values can reach
2^31-1 = 2,147,483,647 (31 bits), they exceed float32's 24-bit exact integer range.
**We cannot naively cast to float for hardware matmul acceleration.**

This constraint shapes the entire optimization strategy: we must optimize the integer
compute path rather than relying on Apple's "tensor core" equivalent.

---

## PHASE 1: Zero-Copy & Allocation Elimination (Est. 2-4x speedup)

### 1A. Metal Buffer Pool (matmul_accel.mm)

**Problem:** 12 Metal buffers (~36 MB) allocated/freed per nonce attempt.

**Solution:** Pre-allocate a reusable buffer pool in `MetalContext`.

```
MetalContext:
  + BufferPool pool;      // Pre-allocated buffers sized for max dimensions
  + Init: allocate all 12 buffers once at context creation
  + ComputeCanonicalTranscriptDigest: memcpy into pooled buffers, skip alloc
```

Files: `src/metal/matmul_accel.mm`
- Add buffer pool fields to `MetalContext` struct (~lines 169-248)
- Remove per-call `newBufferWithLength` calls (~lines 392-405)
- Replace with `memcpy` into pre-allocated buffers
- Keep A/B buffers resident between nonce attempts (they don't change)

### 1B. Keep Base Matrices A,B Resident on GPU

**Problem:** A and B (each 1 MB for n=512) are copied to GPU every nonce attempt,
but they never change between nonce attempts for the same block template.

**Solution:** Upload A,B once per block template. Only upload noise/compress data per nonce.

Files: `src/metal/matmul_accel.h`, `src/metal/matmul_accel.mm`, `src/matmul/accelerated_solver.cpp`
- Add `UploadBaseMatrices(n, matrix_a, matrix_b)` API to Metal layer
- Modify `ComputeCanonicalTranscriptDigest` to accept a "base matrices already uploaded" flag
- Saves ~2 MB memcpy per nonce attempt

### 1C. Eliminate CPU CanonicalMatMul Allocation Storm (transcript.cpp)

**Problem:** 163,840 heap allocations per nonce in the CPU path (5 per iteration × N³ iterations).
`block()` extracts sub-matrices into new `Matrix` objects with `std::vector` storage.

**Solution:** Compute block products in-place using pointer arithmetic into parent matrices.

Files: `src/matmul/transcript.cpp`, `src/matmul/matrix.h`
- Add `block_view()` that returns a lightweight view (pointer + stride) instead of copying
- Rewrite `CanonicalMatMul` inner loop to use views and a single pre-allocated scratch block
- Eliminate `a_block`, `b_block`, `product`, `c_block` temporaries

### 1D. Eliminate CompressBlock Vector Copy (transcript.cpp:71-86)

**Problem:** `CompressBlock` copies block data into a temporary `std::vector<field::Element> flat`
just to call `field::dot`. The Matrix data is already contiguous in row-major order.

**Solution:** Replace with direct `field::dot(block_bb.data(), v.data(), len)`.

Files: `src/matmul/transcript.cpp`
- One-line fix at line 76-85: remove the flat vector, use `block_bb.data()` directly
- Eliminates 32,768 vector allocations per nonce on CPU path

### 1E. Hoist Column Extraction in Matrix::operator* (matrix.cpp:125-133)

**Problem:** Column `j` of `rhs` is extracted for every row `i`, but it only depends on `j`.

**Solution:** Swap loop order or hoist extraction to `j` level.

Files: `src/matmul/matrix.cpp`
- Move `col` extraction loop (lines 128-129) outside the `i` loop
- Saves n × redundant column copies per matrix multiply

---

## PHASE 2: Metal Shader Optimization (Est. 3-8x GPU kernel speedup)

### 2A. Threadgroup Shared Memory Tiling for `build_prefix`

**Problem:** The `build_prefix` kernel reads A' and B' entirely from device (global) memory.
Each element of A' row and B' column is re-read across different threads that share the same
row or column. No data reuse through shared memory.

**Solution:** Implement 2D tiled matrix multiplication using threadgroup shared memory.

```metal
// New kernel structure:
kernel void build_prefix_tiled(
    ...
    uint2 tgid [[threadgroup_position_in_grid]],
    uint2 tid  [[thread_position_in_threadgroup]])
{
    threadgroup uint tile_a[TILE_SIZE][TILE_SIZE];  // e.g., 16x16
    threadgroup uint tile_b[TILE_SIZE][TILE_SIZE];

    // For each block of K dimension:
    //   1. Cooperatively load tile of A' into shared memory
    //   2. Cooperatively load tile of B' into shared memory
    //   3. threadgroup_barrier(mem_flags::mem_threadgroup)
    //   4. Compute partial dot products from shared memory
    //   5. threadgroup_barrier(mem_flags::mem_threadgroup)
}
```

Files: `src/metal/matmul_accel.mm` (kernel source string, lines 101-130)
- Replace scalar 1D `build_prefix` with 2D tiled version
- Use `MTLSizeMake(n, n, 1)` grid with `MTLSizeMake(TILE, TILE, 1)` threadgroups
- TILE_SIZE = 16 matches block size `b`, giving natural alignment with transcript structure
- Each tile load amortizes global memory reads by TILE_SIZE (16x bandwidth reduction)
- Also write `c_prefix` output from registers, reducing write traffic

### 2B. Fused Prefix + Compress Kernel

**Problem:** Two separate kernel dispatches (`build_prefix` then `compress_prefix`) with
an intermediate 32 MB `c_prefix` buffer written then immediately read back.

**Solution:** Fuse into a single kernel that computes the running prefix AND compresses
each (i,j,ell) intermediate on-the-fly, writing only the 128 KB compressed output.

```metal
kernel void fused_prefix_compress(
    ...
    uint2 tgid [[threadgroup_position_in_grid]],  // maps to (row, col) of output
    uint2 tid  [[thread_position_in_threadgroup]])
{
    // Each threadgroup handles one (tile_i, tile_j) output block
    // Loop over ell = 0..N-1:
    //   Compute block product A'[tile_i, ell] * B'[ell, tile_j] using shared memory
    //   Accumulate into c_acc registers
    //   Compress c_acc block using compression vector (from shared memory)
    //   Write compressed scalar to output[i*N*N + j*N + ell]
}
```

Files: `src/metal/matmul_accel.mm`
- Eliminate the `c_prefix` buffer entirely (saves 32 MB allocation for n=512)
- Reduces kernel dispatch overhead from 3 to 2 dispatches
- Eliminates 32 MB intermediate read/write bandwidth

### 2C. GPU-Side SHA256 Transcript Hashing (4th Kernel)

**Problem:** After GPU compress, 128 KB of compressed results are read back to CPU
for SHA256 hashing. This forces a GPU→CPU synchronization stall.

**Solution:** Add a 4th compute kernel that performs SHA256 on the compressed array.
Only the final 32-byte hash needs to come back to CPU.

```metal
kernel void transcript_sha256(
    device const uint* compressed [[buffer(0)]],
    device uint* hash_output [[buffer(1)]],
    constant uint& count [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    // Single-threaded SHA256 over compressed[0..count-1]
    // (Or: parallel prefix SHA256 with tree reduction)
    // Write double-SHA256 result to hash_output
}
```

Files: `src/metal/matmul_accel.mm`
- Implement SHA256 in MSL (standard algorithm, ~100 lines)
- Chain as 4th encoder after compress
- CPU reads back only 32 bytes instead of 128 KB
- Eliminates the CPU-side `CHash256` loop (lines 493-498)

### 2D. Optimal Thread Group Sizing

**Problem:** Thread group size hardcoded to `min(256, max_threads)`. Apple Silicon GPUs
support 1024 threads per threadgroup with 32-wide SIMD groups.

**Solution:** Use device-optimal sizes based on kernel characteristics.

Files: `src/metal/matmul_accel.mm` (EncodeCompute function, line 332)
- For tiled matmul: use TILE×TILE threadgroup (e.g., 16×16 = 256, which is already good)
- For `build_perturbed`: increase to 512 or 1024 (simple kernel, more threads = better occupancy)
- Query `pipeline.maxTotalThreadsPerThreadgroup` and use it
- Add 2D dispatch grids where appropriate

### 2E. Pre-Compiled Metal Shaders (.metallib)

**Problem:** Kernels compiled from inline C strings at first launch. JIT compilation
takes 100-500ms and misses offline compiler optimizations.

**Solution:** Build `.metallib` archives at compile time.

Files: `CMakeLists.txt`, new `src/metal/*.metal` files
- Extract kernel source strings into proper `.metal` source files
- Add CMake rules: `xcrun metal -c *.metal -o *.air && xcrun metallib *.air -o btx.metallib`
- Load pre-compiled library at runtime: `[device newLibraryWithURL:]`
- Keep inline string as fallback for builds without Xcode toolchain

---

## PHASE 3: CPU SIMD & ARM Optimization (Est. 2-4x CPU path speedup)

### 3A. ARM NEON SIMD for field::dot()

**Problem:** `field::dot()` is a scalar loop with per-iteration modular reduction.
This is the innermost hot loop of the entire mining pipeline, called ~328K times per nonce.

**Solution:** NEON-vectorized dot product with lazy reduction.

```cpp
#ifdef __ARM_NEON
#include <arm_neon.h>

Element dot_neon(const Element* a, const Element* b, uint32_t len)
{
    uint64x2_t acc = vdupq_n_u64(0);
    uint32_t i = 0;

    // Process 2 elements at a time
    // Each product is at most (2^31-2)² < 2^62
    // Can safely accumulate ~4 products before uint64 overflow risk
    for (; i + 1 < len; i += 2) {
        uint32x2_t va = vld1_u32(&a[i]);
        uint32x2_t vb = vld1_u32(&b[i]);
        // Widening multiply: uint32×uint32 → uint64
        uint64x2_t prod = vmull_u32(va, vb);
        acc = vaddq_u64(acc, prod);

        // Reduce periodically to prevent overflow (every 4 iterations)
        if ((i & 6) == 6) {
            // Fold each lane: acc = (acc & MODULUS) + (acc >> 31)
            acc = reduce_neon(acc);
        }
    }

    // Horizontal sum + final reduction
    uint64_t sum = vgetq_lane_u64(acc, 0) + vgetq_lane_u64(acc, 1);
    if (i < len) sum += (uint64_t)a[i] * b[i];
    return reduce64(sum);
}
#endif
```

Files: `src/matmul/field.cpp`
- Add `#ifdef __ARM_NEON` path in `dot()` function
- Keep scalar fallback for non-ARM builds
- Expected: 2-4x speedup on M-series CPUs for dot product operations
- Affects both CPU mining path and noise generation (which is CPU even in Metal mode)

### 3B. Branchless Mersenne Reduction

**Problem:** `reduce64()` has a branch: `if (result >= MODULUS) result -= MODULUS`.
Branch misprediction penalty in tight loops.

**Solution:** Branchless conditional subtract.

```cpp
static Element reduce64(uint64_t x)
{
    const uint64_t fold1 = (x & (uint64_t)MODULUS) + (x >> 31);
    const uint32_t lo = (uint32_t)(fold1 & MODULUS);
    const uint32_t hi = (uint32_t)(fold1 >> 31);
    uint32_t result = lo + hi;
    // Branchless: subtract MODULUS if result >= MODULUS
    result -= MODULUS & (uint32_t)(-(int32_t)(result >= MODULUS));
    return result;
}
```

Files: `src/matmul/field.cpp` (line 29-31)
- Also apply to `add()` and `add_mod` in Metal kernel source
- Small but consistent improvement in tight loops

### 3C. Cache-Blocked Matrix Multiply

**Problem:** `Matrix::operator*` has a naive triple loop with poor cache behavior.
Column extraction pattern causes cache misses for the right operand.

**Solution:** Tiled/blocked multiplication with L1-friendly block sizes.

```cpp
Matrix Matrix::operator*(const Matrix& rhs) const
{
    constexpr uint32_t TILE = 32;  // Fits in L1 (32×32×4 = 4KB per tile)
    Matrix out(m_rows, rhs.m_cols);

    for (uint32_t ii = 0; ii < m_rows; ii += TILE) {
        for (uint32_t jj = 0; jj < rhs.m_cols; jj += TILE) {
            for (uint32_t kk = 0; kk < m_cols; kk += TILE) {
                // Micro-kernel: multiply TILE×TILE sub-blocks
                const uint32_t i_end = std::min(ii + TILE, m_rows);
                const uint32_t j_end = std::min(jj + TILE, rhs.m_cols);
                const uint32_t k_end = std::min(kk + TILE, m_cols);

                for (uint32_t i = ii; i < i_end; ++i) {
                    for (uint32_t k = kk; k < k_end; ++k) {
                        const Element a_ik = at(i, k);
                        for (uint32_t j = jj; j < j_end; ++j) {
                            out.at(i, j) = field::add(out.at(i, j),
                                field::mul(a_ik, rhs.at(k, j)));
                        }
                    }
                }
            }
        }
    }
    return out;
}
```

Files: `src/matmul/matrix.cpp` (lines 118-136)
- Tile size 32 chosen for Apple Silicon L1 cache (64 KB, 4-way)
- Inner loop accesses `rhs.at(k, j)` which is now sequential in `j` (row-major)
- The `a_ik` value is register-resident across the `j` loop (scalar broadcast)
- Expected: 2-3x speedup for CPU matrix multiply

### 3D. Lazy Modular Reduction in dot()

**Problem:** `dot()` calls `reduce64()` after every single multiply-add.
Since `acc < 2^31` and `product < 2^62`, `sum < 2^62 + 2^31 < 2^63`.
We can safely accumulate ~4 billion products before uint64 overflow.

**Solution:** Reduce only at the end (or periodically for very long vectors).

Files: `src/matmul/field.cpp` (lines 139-148)
- For len <= 4 (common in noise multiply with r=4,8): eliminate all intermediate reductions
- For larger len: reduce every 64 iterations
- Works with NEON vectorization from 3A

---

## PHASE 4: Pipeline Parallelism (Est. 2-5x throughput improvement)

### 4A. Double-Buffered Metal Command Submission

**Problem:** Synchronous GPU execution: CPU calls `waitUntilCompleted` after each nonce,
blocking both CPU and GPU from overlapping work.

**Solution:** Use a ring of 2-3 command buffers with completion handlers.

```
Timeline:
  CPU: [prepare N+0] [prepare N+1] [prepare N+2] [check N+0] [prepare N+3] ...
  GPU:               [execute N+0] [execute N+1] [execute N+2] [execute N+3] ...
```

Files: `src/metal/matmul_accel.mm`, `src/matmul/accelerated_solver.cpp`
- Add `MetalMiningSession` class that manages:
  - Ring buffer of 2-3 pre-allocated buffer sets
  - Async completion handlers that check digest against target
  - CPU noise generation overlapped with GPU execution
- `SolveMatMul` calls `session.SubmitNonce()` which returns immediately
- Completion handler signals main thread on success

### 4B. Batch Nonce Processing on GPU

**Problem:** Each nonce is processed individually through the full Metal pipeline.
The GPU has massive parallelism that's underutilized processing one nonce at a time.

**Solution:** Process multiple nonces simultaneously on the GPU.

**Key insight:** For different nonces, only the noise matrices and compression vector differ.
Base matrices A and B are identical. We can batch the noise application + matmul + compress
for K nonces in a single GPU dispatch.

```
Per-batch GPU work:
  For K nonces simultaneously:
    1. Apply K different noise perturbations to A,B → K copies of A', B'
    2. Compute K independent transcript matmuls
    3. Compress K transcripts
    4. Hash K compressed results
    5. Check K digests against target
```

Files: `src/metal/matmul_accel.mm`, `src/matmul/accelerated_solver.cpp`
- New kernel: `build_perturbed_batch` with nonce index as an additional grid dimension
- New kernel: `build_prefix_batch` operating on K independent A'/B' pairs
- Batch size K tuned per device: K=4 for M4 base, K=8-16 for M4 Max/Ultra
- Requires K × buffer memory, so K is limited by GPU memory

### 4C. Move Noise Generation to GPU

**Problem:** `noise::Generate` performs 16,384 SHA256 hashes per nonce on the CPU,
even when using the Metal backend. This is ~0.8 ms of CPU-bound work per nonce.

**Solution:** Implement SHA256-based noise matrix generation as a Metal compute kernel.

```metal
kernel void generate_noise_matrix(
    constant uint8_t* seed [[buffer(0)]],    // 32-byte noise seed
    device uint* output [[buffer(1)]],        // n×r output matrix
    constant uint& n [[buffer(2)]],
    constant uint& r [[buffer(3)]],
    uint gid [[thread_position_in_grid]])     // one thread per element
{
    // Each thread computes: SHA256(seed || index) → field element
    // index = gid (maps to row*cols + col)
    // Uses the same from_oracle logic as CPU
}
```

Files: new `src/metal/noise_accel.mm` (or extend `matmul_accel.mm`)
- One thread per noise matrix element (n×r threads per matrix)
- 4 dispatches for E_L, E_R, F_L, F_R (or one with 4× grid)
- Removes the biggest CPU bottleneck in the Metal path
- SHA256 in MSL is straightforward (~100 lines)

### 4D. Compression Vector Generation on GPU

**Problem:** `DeriveCompressionVector` generates b² field elements via SHA256 on CPU.
For b=16 that's 256 SHA256 calls.

**Solution:** Generate on GPU using the same SHA256 kernel as noise.

Files: extend noise generation kernel
- Minor: only 256 elements for b=16, but eliminates another CPU→GPU data dependency

---

## PHASE 5: Apple Silicon Hardware Exploitation

### 5A. Apple AMX (Accelerate Matrix Coprocessor) for CPU Path

**Problem:** The CPU fallback path uses scalar arithmetic. Apple Silicon has a
dedicated matrix coprocessor (AMX) accessible through the Accelerate framework.

**Constraint:** AMX operates on floats, not modular integers. However, for the
noise low-rank product (n×r * r×n where r=4 or 8), the intermediate products
are small enough to fit in float32's exact range if we split the computation.

**Approach:** Use `cblas_sgemm` from Accelerate.framework for the noise products:
- Cast uint32 elements to float (values are 0 to 2^31-2, exceeds float32 exact range)
- **Dual-carry approach:** Split each element: `a = a_hi * 2^16 + a_lo`
- Compute `C = A_hi*B_hi * 2^32 + (A_hi*B_lo + A_lo*B_hi) * 2^16 + A_lo*B_lo`
- Each sub-product involves 16-bit values multiplied → max product 2^32, fits in float32
- 4 float matrix multiplies per modular matrix multiply, but each uses AMX hardware
- For r=4,8 the matrices are skinny, so this may only be beneficial for n ≥ 256

Files: `src/matmul/matrix.cpp` (add `#ifdef __APPLE__` path using `<Accelerate/Accelerate.h>`)
- Only for noise low-rank products (E_L × E_R, F_L × F_R) where matrices are n×r × r×n
- Benchmark to verify AMX overhead is worth it for these small inner dimensions

### 5B. Multi-Core CPU Noise Generation with GCD

**Problem:** Noise generation (16K SHA256 calls) is single-threaded.

**Solution:** Use Grand Central Dispatch to parallelize across P-cores.

```cpp
#ifdef __APPLE__
#include <dispatch/dispatch.h>

Matrix FromSeedRectParallel(const uint256& seed, uint32_t rows, uint32_t cols)
{
    Matrix out(rows, cols);
    dispatch_apply(rows, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^(size_t row) {
            for (uint32_t col = 0; col < cols; ++col) {
                out.at(row, col) = field::from_oracle(seed, row * cols + col);
            }
        });
    return out;
}
#endif
```

Files: `src/matmul/noise.cpp`
- Parallelize the 4 `FromSeedRect` calls across cores
- For n=512, r=8: 4,096 SHA256 per matrix × 4 matrices = 16,384 total
- With 10 P-cores on M4 Pro: ~10x speedup → 0.08 ms instead of 0.8 ms
- Also parallelize `FromSeed` (base matrix generation) and `DeriveCompressionVector`

### 5C. Unified Memory Optimization

**Problem:** Code uses `MTLResourceStorageModeShared` with explicit `memcpy`.
On Apple Silicon, CPU and GPU share the same physical memory.

**Solution:** For data that flows CPU→GPU only, use `MTLResourceStorageModeShared`
but pass CPU-allocated memory directly via `newBufferWithBytesNoCopy:`.

```objc
// Instead of: alloc buffer + memcpy
// Do: wrap existing CPU memory as Metal buffer (zero-copy)
id<MTLBuffer> matrix_a_buffer = [device newBufferWithBytesNoCopy:(void*)request.matrix_a
                                                          length:matrix_bytes
                                                         options:MTLResourceStorageModeShared
                                                     deallocator:nil];
```

Files: `src/metal/matmul_accel.mm`
- Requires that source data is page-aligned (use `posix_memalign` for Matrix storage)
- Eliminates all `memcpy` calls for input data
- `Matrix::m_data` must use page-aligned allocator

### 5D. Metal 4 Cooperative Tensors (Future M5/A19+ Hardware)

**Status:** Metal 4 introduces cooperative tensor types. Currently float-focused
but may expand to integer types on future hardware.

**Preparation:** Structure the tiled matmul kernel (Phase 2A) so that the inner
block multiply can be swapped from manual threadgroup tiling to cooperative tensor
operations when integer support becomes available.

Files: `src/metal/matmul_accel.mm`
- Abstract the inner block multiply behind a preprocessor switch
- When `__METAL_VERSION__ >= 400` and integer cooperative tensors are available,
  use `cooperative_matrix_multiply_accumulate`
- Until then, use manual shared-memory tiling

---

## PHASE 6: Nonce Prefilter Improvements

### 6A. Fix Buffer Overflow Bug (nonce_accel.mm:39)

**Problem:** If more nonces pass the filter than `batch_size`, the atomic index
exceeds the output buffer bounds, causing out-of-bounds GPU memory writes.

**Solution:** Add bounds check in the Metal kernel.

```metal
if (mixed <= threshold) {
    const uint idx = atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed);
    if (idx < batch_size_param) {  // ADD THIS CHECK
        out_nonces[idx] = nonce;
    }
}
```

Files: `src/metal/nonce_accel.mm` (line 39)
- Pass `batch_size` as a kernel parameter
- Critical correctness fix, not just optimization

### 6B. Adaptive Threshold Tuning

**Problem:** Fixed threshold may filter too aggressively or too loosely.

**Solution:** Dynamically adjust threshold based on observed pass rate.

Files: `src/metal/nonce_accel.mm`, `src/btx-genesis.cpp`
- Track pass rate per batch
- If too few candidates pass: increase threshold
- If too many pass: decrease threshold (GPU wasted on prefilter, CPU overwhelmed)
- Target: enough candidates to keep the matmul pipeline fully utilized

---

## PHASE 7: Benchmarking & Profiling Infrastructure

### 7A. Metal GPU Benchmarks

**Problem:** Existing benchmarks only measure the CPU path.

**Solution:** Add Metal-specific benchmarks.

Files: `src/bench/matmul_metal_bench.cpp` (new)
- Benchmark Metal digest computation at mainnet dimensions
- Measure: buffer allocation, data transfer, kernel execution, result readback
- Compare against CPU baseline
- Report GPU utilization via `MTLCounterSampleBuffer` if available

### 7B. Per-Component GPU Profiling

Files: `src/metal/matmul_accel.mm`
- Add optional `MTLCaptureManager` integration for GPU timeline profiling
- Add timing counters per kernel dispatch
- Report via `btx-matmul-backend-info` diagnostic tool

### 7C. Automated Regression Tests for Metal Path

Files: `src/test/matmul_metal_tests.cpp` (new)
- Cross-validate Metal vs CPU results at all supported dimensions
- Test buffer pool reuse correctness
- Test double-buffering correctness
- Test batch nonce processing correctness

---

## Implementation Priority & Expected Impact

| Phase | Change | Effort | Speedup | Priority |
|-------|--------|--------|---------|----------|
| 1A | Metal buffer pool | 1 day | 30-50% | P0 |
| 1B | Resident A,B matrices | 0.5 day | 10-15% | P0 |
| 1C | Eliminate CPU alloc storm | 2 days | 3-5x (CPU) | P0 |
| 1D | CompressBlock direct dot | 1 hour | 5-10% (CPU) | P0 |
| 1E | Hoist column extraction | 1 hour | 10-20% (CPU) | P0 |
| 2A | Threadgroup tiled matmul | 2 days | 3-5x (GPU) | P1 |
| 2B | Fused prefix+compress | 1.5 days | 20-40% (GPU) | P1 |
| 2C | GPU-side SHA256 | 1.5 days | 10-15% (GPU) | P1 |
| 2D | Optimal threadgroup size | 0.5 day | 5-10% | P1 |
| 2E | Pre-compiled metallib | 1 day | startup only | P2 |
| 3A | NEON SIMD dot product | 1.5 days | 2-4x (CPU dot) | P1 |
| 3B | Branchless reduction | 0.5 day | 5-10% | P2 |
| 3C | Cache-blocked matmul | 1 day | 2-3x (CPU mul) | P1 |
| 3D | Lazy reduction | 0.5 day | 10-20% (CPU dot) | P2 |
| 4A | Double-buffered Metal | 2 days | 30-50% | P1 |
| 4B | Batch nonce GPU | 3 days | 2-4x (GPU) | P1 |
| 4C | GPU noise generation | 2 days | 0.8ms/nonce saved | P2 |
| 4D | GPU compress vector | 0.5 day | minor | P3 |
| 5A | AMX for noise products | 2 days | uncertain | P3 |
| 5B | GCD parallel noise gen | 1 day | ~0.7ms saved | P2 |
| 5C | Zero-copy unified mem | 1 day | 10-20% | P2 |
| 5D | Metal 4 cooperative tensors | future | future | P3 |
| 6A | Fix nonce overflow bug | 1 hour | correctness | P0 |
| 6B | Adaptive threshold | 0.5 day | variable | P3 |
| 7A-C | Benchmarks & tests | 2 days | diagnostic | P1 |

---

## Estimated Combined Impact

| Scenario | Current | After Phase 1 | After Ph 1+2 | After Ph 1-4 | After All |
|----------|---------|---------------|--------------|--------------|-----------|
| CPU nonces/sec (n=512) | ~2-5 | ~10-20 | ~10-20 | ~10-20 | ~15-30 |
| Metal nonces/sec (M4) | ~125-500 | ~200-800 | ~600-2500 | ~1200-5000 | ~2000-8000 |
| Metal nonces/sec (M4 Max) | ~400-1500 | ~600-2500 | ~2000-8000 | ~4000-15000 | ~6000-25000 |
| Metal nonces/sec (M4 Ultra est.) | ~800-3000 | ~1200-5000 | ~4000-16000 | ~8000-30000 | ~12000-50000 |

*Ranges reflect uncertainty in memory-bound vs compute-bound regime for each chip.*

---

## Apple Silicon Hardware Reference

| Chip | GPU Cores | Mem BW | Unified Mem | Best For |
|------|-----------|--------|-------------|----------|
| M4 | 10 | 120 GB/s | 32 GB | Dev/testing |
| M4 Pro | 20 | 273 GB/s | 64 GB | Moderate mining |
| M4 Max | 40 | 546 GB/s | 128 GB | Serious mining |
| M4 Ultra (est.) | 80 | ~1 TB/s | 256-512 GB | Maximum throughput |

The MatMul PoW at n=512 is likely **memory-bandwidth-bound** on GPU (the `build_prefix`
kernel reads/writes ~36 MB per nonce). This means M4 Max (546 GB/s) should scale roughly
linearly over M4 Pro (273 GB/s), and M4 Ultra should double M4 Max. Shared memory
tiling (Phase 2A) shifts the balance toward compute-bound, potentially unlocking
superlinear scaling with more GPU cores.

---

## PHASE 8: BTX Unit-of-Account Terminology Migration (parallel with Apple Silicon work)

### 8A. Scope and Design Boundaries

**Goal:** All user-facing monetary units should be presented as `BTX` instead of `BTC`.

**In scope:**
- RPC help/error/result unit labels
- Wallet RPC examples and amount descriptions
- Qt unit display labels and UI placeholders
- Man pages generated from RPC/CLI help
- Tests that assert exact unit strings

**Out of scope for this phase:**
- Consensus math (satoshis, `COIN`, `MAX_MONEY`, chain format)
- Executable/package names (`bitcoind`, `bitcoin-cli`, `bitcoin-qt`) to avoid release/package churn
- Historical release notes text that is intentionally archival

### 8B. Required Code Changes (deep scan results)

| Area | Files | Required change | Dependency / break risk |
|------|-------|-----------------|--------------------------|
| Global currency label | `src/policy/feerate.h`, `src/policy/feerate.cpp` | Switch `CURRENCY_UNIT` to `BTX`; update `BTC/kvB` comments to `BTX/kvB` | Cascades into RPC help text, CLI output, and tests |
| Fee mode enum naming | `src/policy/feerate.h`, `src/test/amount_tests.cpp` | Evaluate renaming `FeeEstimateMode::BTC_KVB` to a neutral name (`UNIT_KVB`) or keep enum but update displayed strings only | Renaming can break internal callsites; keeping enum minimizes churn |
| RPC help and wallet text that already use `CURRENCY_UNIT` | `src/init.cpp`, `src/rpc/*.cpp`, `src/wallet/init.cpp`, `src/wallet/rpc/*.cpp`, `src/bitcoin-cli.cpp` | Mostly automatic after `CURRENCY_UNIT` update; verify all generated strings | Functional tests parse exact key names like `(.../kvB)` |
| Hardcoded BTC literals in examples/help | `src/wallet/rpc/spend.cpp`, `src/rpc/util.h`, `src/rpc/mining.cpp` | Replace hardcoded `BTC` examples with `BTX` | Tests comparing error/help text can fail |
| Qt default unit and labels | `src/qt/bitcoinunits.cpp`, `src/qt/bitcoinunits.h`, `src/qt/optionsmodel.cpp`, `src/qt/overviewpage.cpp`, `src/qt/blockview.cpp`, `src/qt/guiutil.cpp`, `src/qt/psbtoperationsdialog.cpp`, `src/qt/bitcoinamountfield.cpp`, `src/qt/coincontroldialog.cpp`, `src/qt/forms/*.ui` | Change displayed unit short/long names and placeholder text to `BTX`; ensure default display still maps to index 0 | Settings compatibility: avoid changing serialized unit IDs unless migration is explicit |
| Man pages | `doc/man/bitcoind.1`, `doc/man/bitcoin-qt.1` | Regenerate after help text changes to update `BTC/kvB` references | CI/doc checks can fail if generated docs are stale |
| General comments/docs | `src/consensus/amount.h`, selected docs/tests | Update where wording is user-facing; keep archival/historical references untouched | Avoid excessive churn in non-user-facing comments |

### 8C. Dependency-Safe Migration Strategy

1. Change `CURRENCY_UNIT` to `BTX` and keep formatting logic stable.
2. Update remaining hardcoded wallet/RPC examples (`Send 0.1 BTC`, `0.5 BTC`, etc.).
3. Update Qt display strings/placeholders to `BTX`, but preserve stable serialized unit ID behavior.
4. Update unit/functional tests with strict string expectations.
5. Regenerate man pages and rerun doc checks.
6. Run targeted and full CI before merging.

### 8D. Tests Expected to Change

**High-confidence strict-string tests:**
- `src/test/amount_tests.cpp`
- `test/functional/interface_bitcoin_cli.py`
- `test/functional/wallet_fundrawtransaction.py`
- `test/functional/rpc_psbt.py`
- `test/functional/mempool_accept.py`
- `test/functional/feature_rbf.py`

**Likely collateral updates (comments/log text and minor assertions):**
- `test/functional/rpc_rawtransaction.py`
- `test/functional/test_framework/util.py`
- selected wallet/transaction functional tests that mention BTC in expected text

### 8E. Apple Silicon Optimization Test + Benchmark Gate (must exist before implementation close)

**Unit/integration gates:**
- `build/bin/test_btx --run_test=matmul_accelerated_solver_tests`
- `build/bin/test_btx --run_test=matmul_backend_capabilities_tests`
- `build/bin/test_btx --run_test=matmul_transcript_tests`
- `build/bin/test_btx --run_test=matmul_pow_tests`

**Functional gates:**
- `test/functional/feature_btx_genesis_readiness.py`
- targeted wallet/RPC tests impacted by BTX terminology migration

**Benchmark gates:**
- `build/bin/bench_btx -list | rg -i matmul`
- `build/bin/bench_btx -filter='MatMulSolveMainnetDimensions|MatMulSolveTestnetDimensions' -min-time=50`
- Planned new benchmark target from Phase 7A: `src/bench/matmul_metal_bench.cpp`

**CI gates:**
- full branch CI (Linux/macOS/Windows, sanitizer and functional jobs)
- no regressions in unit, functional, fuzz smoke, and doc/manpage checks

### 8F. Local Apple Silicon Sanity Check (2026-02-19)

Host:
- `uname -m`: `arm64`
- `sw_vers -productVersion`: `15.0`

Local verification performed:
- `build/bin/test_btx --run_test=matmul_accelerated_solver_tests` -> pass
- `build/bin/test_btx --run_test=matmul_backend_capabilities_tests` -> pass
- `build/bin/bench_btx -list | rg -i matmul` -> `MatMulSolveMainnetDimensions`, `MatMulSolveTestnetDimensions`
- `build/bin/bench_btx -filter='MatMulSolveMainnetDimensions|MatMulSolveTestnetDimensions' -min-time=50` ->
  - Mainnet dimensions mean: `421.529695 ms`
  - Testnet dimensions mean: `75.365362 ms`

Interpretation:
- This machine is suitable for iterative Metal profiling and sanity benchmarking.
- Absolute numbers are local baselines only; use CI and controlled benchmark hosts for release comparisons.

### 8G. Deliverables for Next Coding Sessions

- Implement Phases 1-7 Apple Silicon improvements with regression tests and benches.
- Execute Phase 8 BTX terminology migration with dependency-safe sequencing.
- Keep man pages and functional tests synchronized with user-facing unit text.
- Land changes in small, reviewable commits grouped by area:
  - `metal/perf`
  - `rpc-wallet-unit-labels`
  - `qt-unit-display`
  - `tests-docs-sync`
