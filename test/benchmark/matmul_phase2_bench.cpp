// =============================================================================
// BTX MatMul PoW -- Phase 2 Verification Benchmark
// =============================================================================
//
// Standalone benchmark for Phase 2 (full O(n^3) canonical matmul recomputation)
// over the M31 field (q = 2^31 - 1).
//
// Implements the exact algorithms from btx-matmul-pow-spec.md v3:
//   - reduce64: double Mersenne fold (SS7.2.3-7.2.4)
//   - mul(a,b): reduce64((uint64_t)a * b) (SS7.2.4)
//   - dot(a,b,len): per-step reduction (SS7.2.5)
//   - FromSeed: n^2 SHA-256 calls with rejection sampling (SS7.4.3)
//   - Naive n x n matmul using dot() for each output element
//   - Transcript compression: (n/b)^3 dot products of length b^2 (SS8.3.1)
//   - Noise generation: 4*n*r SHA-256 calls (SS8.2.1)
//
// Uses BTX's consensus SHA-256 implementation (crypto/sha256.h).
//
// Build:
//   g++ -O2 -std=c++17 -o matmul_bench matmul_phase2_bench.cpp -lcrypto
//
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <random>
#include <algorithm>

#include <crypto/sha256.h>

// =============================================================================
// M31 Field Arithmetic (SS7.1, SS7.2)
// =============================================================================

namespace m31 {

using Element = uint32_t;
constexpr Element MODULUS = 0x7FFFFFFFU; // 2^31 - 1

// reduce64: Reduces any uint64_t to [0, MODULUS) via double Mersenne fold.
// Safe for ALL uint64_t inputs (SS7.2.3-7.2.4).
//
// Cost: 2 shifts, 3 masks/adds, 1 conditional subtract.
static inline Element reduce64(uint64_t x) {
    // --- FIRST FOLD ---
    // 2^31 = 1 (mod q), so x mod q = (x mod 2^31 + x/2^31) mod q.
    // hi_1 can be up to 2^33 - 1 (33 bits); must stay in uint64_t.
    uint64_t fold1 = (x & (uint64_t)MODULUS) + (x >> 31);
    // fold1 in [0, 5*2^31 - 2], fits in 34 bits of uint64_t.

    // --- SECOND FOLD ---
    // fold1 >> 31 <= 4, so lo_2 + hi_2 <= 2^31 + 3 < 2*q.
    uint32_t lo = (uint32_t)(fold1 & MODULUS);
    uint32_t hi = (uint32_t)(fold1 >> 31);
    uint32_t result = lo + hi;

    // --- FINAL CONDITIONAL SUBTRACT ---
    // result in [0, 2^31 + 3]. Since 2^31 + 3 < 2*q = 2^32 - 2,
    // at most one subtract yields result in [0, q).
    if (result >= MODULUS) result -= MODULUS;
    return result;
}

// sub: (a - b) mod q
static inline Element sub(Element a, Element b) {
    return (a >= b) ? (a - b) : (a + MODULUS - b);
}

// mul: Multiply two field elements (SS7.2.4).
// a, b in [0, q). Product in [0, (2^31-2)^2] < 2^62.
static inline Element mul(Element a, Element b) {
    return reduce64((uint64_t)a * b);
}

// dot: Inner product with per-step reduction (SS7.2.5).
// This is the ONLY approved accumulation path.
// Safe for ANY len -- per-step reduction makes it length-independent.
static Element dot(const Element* a, const Element* b, uint32_t len) {
    Element acc = 0; // acc in [0, q) -- invariant holds trivially at start

    for (uint32_t i = 0; i < len; ++i) {
        // a[i], b[i] in [0, q), so product in [0, (q-1)^2] < 2^62
        uint64_t product = (uint64_t)a[i] * b[i];

        // acc < q < 2^31, product < 2^62
        // sum < 2^31 + 2^62 < 2^63 -- no uint64 overflow
        uint64_t sum = (uint64_t)acc + product;

        // reduce64 is safe for all uint64; here sum < 2^62 so the
        // second fold is a no-op. Result is in [0, q), restoring invariant.
        acc = reduce64(sum);
    }

    return acc;
}

} // namespace m31

// =============================================================================
// SHA-256 helpers
// =============================================================================

static void write_le32(uint8_t* buf, uint32_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

static uint32_t read_le32(const uint8_t* buf) {
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

static void sha256_once(const uint8_t* data, size_t len, uint8_t out[32]) {
    CSHA256().Write(data, len).Finalize(out);
}

// from_oracle: Deterministic field element from seed + index (SS7.4.6).
// SHA-256 based with rejection sampling for uniform distribution mod M31.
static m31::Element from_oracle(const uint8_t seed[32], uint32_t index) {
    for (uint32_t retry = 0; retry < 256; ++retry) {
        uint8_t preimage[40];
        std::memcpy(preimage, seed, 32);
        uint8_t idx_le[4];
        write_le32(idx_le, index);
        std::memcpy(preimage + 32, idx_le, 4);
        size_t preimage_len = 36;

        if (retry > 0) {
            uint8_t retry_le[4];
            write_le32(retry_le, retry);
            std::memcpy(preimage + 36, retry_le, 4);
            preimage_len = 40;
        }

        uint8_t hash[32];
        sha256_once(preimage, preimage_len, hash);

        // Extract bytes 0-3 as little-endian uint32, mask to 31 bits
        uint32_t candidate = read_le32(hash) & m31::MODULUS;

        if (candidate < m31::MODULUS) {
            return candidate;
        }
    }
    // Unreachable in practice (probability ~= 10^-2450)
    return 0;
}

// =============================================================================
// Matrix operations
// =============================================================================

using Matrix = std::vector<m31::Element>;

// FromSeed: Generate n x n matrix via n^2 from_oracle calls (SS7.4.3).
// Row-major: M[row][col] = from_oracle(seed, row * n + col)
static Matrix from_seed(const uint8_t seed[32], uint32_t n) {
    Matrix M(n * n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            M[row * n + col] = from_oracle(seed, row * n + col);
        }
    }
    return M;
}

// Naive n x n matrix multiply over M31 using dot() for each output element.
// C[i][j] = dot(A_row_i, B_col_j, n)
// Row-major storage for A, C. B is accessed column-wise.
static Matrix matmul_naive(const Matrix& A, const Matrix& B, uint32_t n) {
    Matrix C(n * n);

    // We need column-stride access for B, so extract columns
    // into a temporary buffer for each j to get contiguous data for dot().
    std::vector<m31::Element> B_col(n);

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            // Extract column j of B
            for (uint32_t k = 0; k < n; ++k) {
                B_col[k] = B[k * n + j];
            }
            C[i * n + j] = m31::dot(&A[i * n], B_col.data(), n);
        }
    }

    return C;
}

// =============================================================================
// Transcript compression simulation (SS8.3.1)
// =============================================================================

// Compression: for each (n/b)^3 block intermediates, compute one dot product
// of length b^2 between the flattened b x b block and a compression vector.
// This measures the dominant cost: the field arithmetic of compression.
static void bench_compression(const Matrix& C, uint32_t n, uint32_t b,
                               double& elapsed_ms, uint64_t& num_ops) {
    uint32_t nb = n / b; // number of blocks per dimension
    uint32_t b2 = b * b;

    // Generate a fake compression vector (in real protocol, derived from sigma)
    std::vector<m31::Element> v(b2);
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint32_t> dist(0, m31::MODULUS - 1);
    for (uint32_t i = 0; i < b2; ++i) {
        v[i] = dist(rng);
    }

    // Temporary buffer for flattened b x b block
    std::vector<m31::Element> block_buf(b2);

    auto t0 = std::chrono::high_resolution_clock::now();

    volatile m31::Element sink = 0;

    // For each block triple (bi, bj, bk), compress the b x b intermediate
    // In the actual protocol, this runs for (n/b)^3 intermediates.
    // Each intermediate is a b x b sub-block of C.
    // Here we simulate by iterating over (n/b)^2 output blocks and
    // doing nb compression dot-products per output block (one per bk step).
    for (uint32_t bi = 0; bi < nb; ++bi) {
        for (uint32_t bj = 0; bj < nb; ++bj) {
            // Extract the b x b block from C at block position (bi, bj)
            for (uint32_t r = 0; r < b; ++r) {
                for (uint32_t c = 0; c < b; ++c) {
                    block_buf[r * b + c] = C[(bi * b + r) * n + (bj * b + c)];
                }
            }

            // In the real protocol, each (bi, bj) output block accumulates
            // over nb values of bk. We simulate nb compression calls per block.
            for (uint32_t bk = 0; bk < nb; ++bk) {
                m31::Element compressed = m31::dot(block_buf.data(), v.data(), b2);
                sink = compressed; // prevent optimization
            }
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    num_ops = (uint64_t)nb * nb * nb * b2; // total multiply-adds
    (void)sink;
}

// Denoise benchmark for C_clean = C_noisy - E_L*F_R - F_L*E_R.
// Measures the O(n^2 * r) path explicitly.
static double bench_denoise(uint32_t n, uint32_t r) {
    std::mt19937 rng(4242 + n + r);
    std::uniform_int_distribution<uint32_t> dist(0, m31::MODULUS - 1);

    Matrix C_noisy(n * n);
    Matrix E_L(n * r);
    Matrix E_R(r * n);
    Matrix F_L(n * r);
    Matrix F_R(r * n);
    Matrix C_clean(n * n);

    for (uint32_t i = 0; i < n * n; ++i) C_noisy[i] = dist(rng);
    for (uint32_t i = 0; i < n * r; ++i) {
        E_L[i] = dist(rng);
        F_L[i] = dist(rng);
    }
    for (uint32_t i = 0; i < r * n; ++i) {
        E_R[i] = dist(rng);
        F_R[i] = dist(rng);
    }

    auto t0 = std::chrono::high_resolution_clock::now();

    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            m31::Element ef = 0;
            m31::Element fe = 0;
            for (uint32_t k = 0; k < r; ++k) {
                ef = m31::reduce64((uint64_t)ef + (uint64_t)E_L[i * r + k] * F_R[k * n + j]);
                fe = m31::reduce64((uint64_t)fe + (uint64_t)F_L[i * r + k] * E_R[k * n + j]);
            }
            const uint32_t idx = i * n + j;
            C_clean[idx] = m31::sub(m31::sub(C_noisy[idx], ef), fe);
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();

    volatile m31::Element sink = C_clean[0];
    (void)sink;
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

// =============================================================================
// Noise generation benchmark (SS8.2.1)
// =============================================================================

// Noise generation requires 4*n*r SHA-256 calls for the four rank-r factors
// (E_L, E_R, F_L, F_R).
static double bench_noise_gen(uint32_t n, uint32_t r) {
    // Use a dummy seed and domain prefix (the actual protocol uses
    // domain-separated seeds like "matmul_noise_EL_v1" etc.)
    uint8_t seed[32] = {};
    seed[0] = 0xAA; // arbitrary

    auto t0 = std::chrono::high_resolution_clock::now();

    volatile m31::Element sink = 0;
    uint32_t total_calls = 4 * n * r;

    for (uint32_t i = 0; i < total_calls; ++i) {
        m31::Element e = from_oracle(seed, i);
        sink = e;
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

// =============================================================================
// Timing helpers
// =============================================================================

struct BenchResult {
    uint32_t n;
    double matmul_ms;
    uint64_t field_muls;     // n^3
    double muls_per_sec;
    double cpu_pct_90s;      // CPU% at 90s block interval
    double cpu_pct_025s;     // CPU% at 0.25s block interval (fast phase)
};

static BenchResult bench_matmul(uint32_t n) {
    BenchResult res{};
    res.n = n;
    res.field_muls = (uint64_t)n * n * n;

    // Generate random matrices (using rand, not FromSeed, for speed at small n)
    Matrix A(n * n), B(n * n);
    std::mt19937 rng(12345 + n);
    std::uniform_int_distribution<uint32_t> dist(0, m31::MODULUS - 1);
    for (uint32_t i = 0; i < n * n; ++i) {
        A[i] = dist(rng);
        B[i] = dist(rng);
    }

    // Warm up
    if (n <= 128) {
        Matrix warm = matmul_naive(A, B, n);
        (void)warm;
    }

    // Time the matmul
    auto t0 = std::chrono::high_resolution_clock::now();
    Matrix C = matmul_naive(A, B, n);
    auto t1 = std::chrono::high_resolution_clock::now();

    res.matmul_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    res.muls_per_sec = (double)res.field_muls / (res.matmul_ms / 1000.0);
    res.cpu_pct_90s = (res.matmul_ms / 1000.0) / 90.0 * 100.0;
    res.cpu_pct_025s = (res.matmul_ms / 1000.0) / 0.25 * 100.0;

    return res;
}

// =============================================================================
// Verification of correctness
// =============================================================================

static bool verify_field_arithmetic() {
    printf("  Verifying M31 field arithmetic...\n");
    bool ok = true;

    // reduce64 edge cases (SS7.2 test vectors)
    auto check = [&](uint64_t input, uint32_t expected, const char* label) {
        uint32_t got = m31::reduce64(input);
        if (got != expected) {
            printf("    FAIL: reduce64(%s) = %u, expected %u\n", label, got, expected);
            ok = false;
        }
    };

    check(0, 0, "0");
    check(1, 1, "1");
    check(m31::MODULUS, 0, "MODULUS");
    check((uint64_t)m31::MODULUS + 1, 1, "MODULUS+1");
    check((uint64_t)m31::MODULUS * m31::MODULUS, 0, "MODULUS^2");
    check((uint64_t)(m31::MODULUS - 1) * (m31::MODULUS - 1), 1, "(MODULUS-1)^2");
    check(1ULL << 63, 2, "2^63");
    check((1ULL << 63) - 1, 1, "2^63-1");
    check(UINT64_MAX, 3, "UINT64_MAX");

    // mul test
    m31::Element a = m31::MODULUS - 1; // q-1
    m31::Element b = m31::MODULUS - 1;
    if (m31::mul(a, b) != 1) {
        printf("    FAIL: mul(q-1, q-1) != 1\n");
        ok = false;
    }

    // dot test: dot of two vectors of all (q-1) with length 4 should give 4
    m31::Element va[4] = {m31::MODULUS - 1, m31::MODULUS - 1, m31::MODULUS - 1, m31::MODULUS - 1};
    m31::Element vb[4] = {m31::MODULUS - 1, m31::MODULUS - 1, m31::MODULUS - 1, m31::MODULUS - 1};
    if (m31::dot(va, vb, 4) != 4) {
        printf("    FAIL: dot(all q-1, all q-1, 4) != 4\n");
        ok = false;
    }

    // dot of empty vector should be 0
    if (m31::dot(va, vb, 0) != 0) {
        printf("    FAIL: dot(_, _, 0) != 0\n");
        ok = false;
    }

    if (ok) printf("    All field arithmetic checks passed.\n");
    return ok;
}

static bool verify_from_oracle() {
    printf("  Verifying from_oracle (TV1 from spec)...\n");

    // TV1: from_oracle(seed=0x00..00, index=0) should give 1432335981
    uint8_t seed[32] = {};
    m31::Element result = from_oracle(seed, 0);
    if (result != 1432335981U) {
        printf("    FAIL: from_oracle(0x00..00, 0) = %u, expected 1432335981\n", result);
        return false;
    }
    printf("    TV1 passed: from_oracle(0x00..00, 0) = %u\n", result);
    return true;
}

// =============================================================================
// Main benchmark
// =============================================================================

int main() {
    printf("====================================================================\n");
    printf("  BTX MatMul PoW -- Phase 2 Verification Benchmark\n");
    printf("  Field: M31 (q = 2^31 - 1 = 2,147,483,647)\n");
    printf("  Spec:  btx-matmul-pow-spec.md v3\n");
    printf("====================================================================\n\n");

    // ---- Correctness verification ----
    printf("--- Correctness Checks ---\n");
    bool field_ok = verify_field_arithmetic();
    bool oracle_ok = verify_from_oracle();
    if (!field_ok || !oracle_ok) {
        printf("\nFATAL: Correctness checks failed. Aborting benchmark.\n");
        return 1;
    }
    printf("\n");

    // ---- MatMul benchmarks for all dimensions ----
    printf("--- Phase 2 MatMul Benchmark (single-threaded, O(n^3) naive) ---\n\n");

    const uint32_t dims[] = {64, 128, 256, 512};
    const char* labels[] = {"regtest", "", "testnet", "mainnet"};
    std::vector<BenchResult> results;

    printf("  %-6s  %-10s  %14s  %14s  %12s  %12s  %s\n",
           "n", "Label", "Time (ms)", "Muls/sec", "CPU%@90s", "CPU%@0.25s", "Field muls (n^3)");
    printf("  %-6s  %-10s  %14s  %14s  %12s  %12s  %s\n",
           "------", "----------", "--------------", "--------------",
           "------------", "------------", "----------------");

    for (int i = 0; i < 4; ++i) {
        uint32_t n = dims[i];
        printf("  Benchmarking n=%u...", n);
        fflush(stdout);

        BenchResult res = bench_matmul(n);
        results.push_back(res);

        printf("\r  %-6u  %-10s  %14.2f  %14.3e  %11.3f%%  %11.1f%%  %llu\n",
               n, labels[i],
               res.matmul_ms,
               res.muls_per_sec,
               res.cpu_pct_90s,
               res.cpu_pct_025s,
               (unsigned long long)res.field_muls);
    }

    printf("\n");

    // ---- Component breakdown for n=512 (mainnet) ----
    printf("--- Component Breakdown for n=512 (mainnet), b=16, r=8 ---\n\n");

    const uint32_t N = 512;
    const uint32_t B = 16;
    const uint32_t R = 8;

    // Use the matmul result we already have
    BenchResult& main_res = results[3]; // n=512

    // FromSeed benchmark (n^2 SHA-256 calls)
    printf("  Benchmarking FromSeed (n=%u, %u SHA-256 calls)...", N, N * N);
    fflush(stdout);
    uint8_t test_seed[32] = {};
    test_seed[0] = 0x42;

    auto t0 = std::chrono::high_resolution_clock::now();
    Matrix A_fs = from_seed(test_seed, N);
    auto t1 = std::chrono::high_resolution_clock::now();
    double fromseed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    printf(" done.\n");

    // Noise generation benchmark (4*n*r SHA-256 calls)
    uint32_t noise_sha_calls = 4 * N * R;
    printf("  Benchmarking noise generation (4*%u*%u = %u SHA-256 calls)...", N, R, noise_sha_calls);
    fflush(stdout);
    double noise_ms = bench_noise_gen(N, R);
    printf(" done.\n");

    // Transcript compression benchmark
    // Need a matrix for compression -- reuse the FromSeed matrix as a fake C
    // Generate a second matrix to multiply for a real C
    printf("  Benchmarking transcript compression ((n/b)^3 = %u dot products of len b^2 = %u)...",
           (N / B) * (N / B) * (N / B), B * B);
    fflush(stdout);

    // Generate random matrices for compression test
    Matrix C_for_comp(N * N);
    {
        std::mt19937 rng(99);
        std::uniform_int_distribution<uint32_t> dist(0, m31::MODULUS - 1);
        for (uint32_t i = 0; i < N * N; ++i) C_for_comp[i] = dist(rng);
    }

    double compress_ms = 0.0;
    uint64_t compress_ops = 0;
    bench_compression(C_for_comp, N, B, compress_ms, compress_ops);
    printf(" done.\n");

    printf("  Benchmarking denoise (O(n^2*r), n=%u, r=%u)...", N, R);
    fflush(stdout);
    double denoise_ms = bench_denoise(N, R);
    printf(" done.\n");

    printf("\n");
    printf("  %-35s  %12s  %14s  %12s\n",
           "Component", "Time (ms)", "Field muls", "% of MatMul");
    printf("  %-35s  %12s  %14s  %12s\n",
           "-----------------------------------", "------------", "--------------", "------------");

    double matmul_ms_512 = main_res.matmul_ms;
    uint64_t matmul_muls_512 = (uint64_t)N * N * N; // 134,217,728

    printf("  %-35s  %12.2f  %14llu  %11.1f%%\n",
           "MatMul (n^3 baseline)",
           matmul_ms_512,
           (unsigned long long)matmul_muls_512,
           100.0);

    printf("  %-35s  %12.2f  %14s  %11.1f%%\n",
           "FromSeed (n^2 SHA-256 calls)",
           fromseed_ms,
           "(SHA-256)",
           fromseed_ms / matmul_ms_512 * 100.0);

    printf("  %-35s  %12.2f  %14s  %11.1f%%\n",
           "Noise gen (4*n*r SHA-256 calls)",
           noise_ms,
           "(SHA-256)",
           noise_ms / matmul_ms_512 * 100.0);

    printf("  %-35s  %12.2f  %14llu  %11.1f%%\n",
           "Transcript compression dot-prods",
           compress_ms,
           (unsigned long long)compress_ops,
           compress_ms / matmul_ms_512 * 100.0);

    const uint64_t denoise_ops = 4ULL * N * N * R;
    printf("  %-35s  %12.2f  %14llu  %11.1f%%\n",
           "Denoise (4*n^2*r)",
           denoise_ms,
           (unsigned long long)denoise_ops,
           denoise_ms / matmul_ms_512 * 100.0);

    double total_ms = matmul_ms_512 + fromseed_ms + noise_ms + compress_ms + denoise_ms;
    printf("  %-35s  %12.2f  %14s  %11.1f%%\n",
           "TOTAL (Phase 2 verification)",
           total_ms,
           "",
           total_ms / matmul_ms_512 * 100.0);

    printf("\n");

    // ---- Comparison to spec estimates (Section 3.5.2) ----
    printf("--- Comparison to Spec Estimates (Section 3.5.2) ---\n\n");

    printf("  Spec estimates for n=512 Phase 2 on a modern CPU:\n");
    printf("    Modern x86 (Zen 4):     ~0.5 s  (~0.6%% CPU @ 90s)\n");
    printf("    Modern ARM (Apple M2):  ~0.7 s  (~0.8%% CPU @ 90s)\n");
    printf("    Older x86 (Haswell):    ~1.5-2 s (~1.7-2.2%% CPU @ 90s)\n");
    printf("    Low-end ARM (RPi 4):    ~4-6 s  (~4.4-6.7%% CPU @ 90s)\n\n");

    printf("  This hardware (n=512):\n");
    printf("    MatMul time:            %.3f s\n", matmul_ms_512 / 1000.0);
    printf("    Total Phase 2 time:     %.3f s\n", total_ms / 1000.0);
    printf("    Throughput:             %.3e field muls/sec\n", main_res.muls_per_sec);
    printf("    CPU util @ 90s blocks:  %.3f%%\n", main_res.cpu_pct_90s);
    printf("    CPU util @ 0.25s blocks: %.1f%%\n", main_res.cpu_pct_025s);
    printf("\n");

    // ---- Protocol overhead analysis ----
    printf("--- Protocol Overhead Analysis (n=512, b=16, r=8) ---\n\n");

    // Spec overhead table values
    uint64_t spec_noise_muls = 2ULL * N * N * R;        // 4.2M for noise factor products
    uint64_t spec_compress_muls = (uint64_t)N * N * N / B; // n^3/b = 8.4M
    uint64_t spec_denoise_muls = 4ULL * N * N * R;      // 8.4M for denoising
    uint64_t spec_total_overhead = spec_noise_muls + spec_compress_muls + spec_denoise_muls;

    printf("  Spec overhead table (SS2.8):\n");
    printf("    Noisy MatMul baseline:   %12llu field muls (100%%)\n",
           (unsigned long long)matmul_muls_512);
    printf("    Noise gen (O(n^2*r)):    %12llu field muls (%.1f%%)\n",
           (unsigned long long)spec_noise_muls,
           (double)spec_noise_muls / matmul_muls_512 * 100.0);
    printf("    Compression (n^3/b):     %12llu field muls (%.1f%%)\n",
           (unsigned long long)spec_compress_muls,
           (double)spec_compress_muls / matmul_muls_512 * 100.0);
    printf("    Denoising (4*n^2*r):     %12llu field muls (%.1f%%)\n",
           (unsigned long long)spec_denoise_muls,
           (double)spec_denoise_muls / matmul_muls_512 * 100.0);
    printf("    Total overhead:          %12llu field muls (%.1f%%)\n",
           (unsigned long long)spec_total_overhead,
           (double)spec_total_overhead / matmul_muls_512 * 100.0);
    printf("\n");

    // ---- Feasibility summary ----
    printf("--- Feasibility Summary ---\n\n");

    double phase2_total_s = total_ms / 1000.0;
    bool feasible_90s = phase2_total_s < 45.0;   // must finish in <45s (half of 90s)
    bool feasible_025s = phase2_total_s < 0.25;

    printf("  Phase 2 total time (n=512): %.3f s\n", phase2_total_s);
    printf("  Steady-state (90s blocks):  %s (%.3f%% CPU)\n",
           feasible_90s ? "FEASIBLE" : "NOT FEASIBLE",
           total_ms / 1000.0 / 90.0 * 100.0);
    printf("  Fast phase (0.25s blocks):  %s (%.1f%% CPU)\n",
           feasible_025s ? "FEASIBLE -- single core keeps up" :
                           "REQUIRES GPU or deferred queue",
           total_ms / 1000.0 / 0.25 * 100.0);
    printf("\n");

    // ---- Scaling analysis ----
    printf("--- Scaling Analysis (n^3 growth) ---\n\n");

    if (results.size() >= 2) {
        printf("  %-6s -> %-6s  %10s  %10s\n",
               "n_low", "n_high", "Time ratio", "Expected (8x)");
        printf("  %-6s    %-6s  %10s  %10s\n",
               "------", "------", "----------", "-------------");
        for (size_t i = 1; i < results.size(); ++i) {
            double ratio = results[i].matmul_ms / results[i - 1].matmul_ms;
            double expected = (double)(results[i].n * results[i].n * results[i].n) /
                              (double)(results[i-1].n * results[i-1].n * results[i-1].n);
            printf("  %-6u -> %-6u  %10.2f  %10.1f\n",
                   results[i - 1].n, results[i].n, ratio, expected);
        }
        printf("\n  (Ratio should approach n^3 scaling = 8x per doubling of n)\n");
    }

    printf("\n====================================================================\n");
    printf("  Benchmark complete.\n");
    printf("====================================================================\n");

    return 0;
}
