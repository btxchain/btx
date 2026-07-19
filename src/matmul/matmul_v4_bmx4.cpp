// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_bmx4.h>

#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>

namespace matmul::v4::bmx4 {
namespace {

// V4.2 domain-separation tags (design §2.3). Distinct from the v4.1 "_V4"
// tags so the two encoding profiles are cryptographically independent objects.
constexpr char kSeedTagV42[] = "BTX_MATMUL_SEED_V42";
constexpr char kProjectorUTagV42[] = "BTX_MATMUL_V42_SKETCH_U";
constexpr char kProjectorVTagV42[] = "BTX_MATMUL_V42_SKETCH_V";

// V4.2-D domain-separation tags (ENC-BMX4C-D deeper-commit profile). Distinct
// from the V42 (C-profile) tags so the two profiles are cryptographically
// independent objects: a seed can never yield correlated C/D operand streams.
constexpr char kSeedTagV42D[] = "BTX_MATMUL_SEED_V42D";
constexpr char kProjectorUTagV42D[] = "BTX_MATMUL_V42D_SKETCH_U";
constexpr char kProjectorVTagV42D[] = "BTX_MATMUL_V42D_SKETCH_V";

// XOF stream domain bytes for the two operand planes. Distinct from the
// existing int8_field streams ('s' = 0x73, 'q' = 0x71) so a seed can never
// yield correlated mantissa/scale/s8/Fq keystreams.
constexpr uint8_t kMantissaStreamDomain = 0x6D; // 'm'
constexpr uint8_t kScaleStreamDomain = 0x65;    // 'e'

// Little-endian byte image of a uint256 (matches int8_field::SeedBytesLE, the
// repo-wide seed byte convention).
void SeedBytesLE(const uint256& seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; ++i) {
        out[i] = seed.data()[31 - i];
    }
}

uint256 DeriveTaggedSeed(const char* tag, size_t taglen, const uint256& hash,
                         const uint8_t* which, size_t which_len)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(hash.data(), uint256::size());
    if (which_len) hasher.Write(which, which_len);
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

// Pinned nibble -> (accepted, mantissa) E2M1 decode table, built once. See
// SampleMantissaNibble for the derivation. Index is the 4-bit nibble value.
struct MantissaTable {
    std::array<int8_t, 16> value{};
    std::array<bool, 16> accepted{};
    constexpr MantissaTable()
    {
        // FP4 E2M1 magnitude by (exp, man): exp0 -> {0, .5}, exp1 -> {1, 1.5},
        // exp2 -> {2, 3}, exp3 -> {4, 6}. Half-integer codes (.5, 1.5) and the
        // negative-zero code are holes.
        for (uint8_t nib = 0; nib < 16; ++nib) {
            const uint8_t sign = (nib >> 3) & 1;
            const uint8_t exp = (nib >> 1) & 3;
            const uint8_t man = nib & 1;
            int mag = 0;
            bool integer = true;
            switch (exp) {
            case 0: mag = 0; integer = (man == 0); break; // 0 or 0.5
            case 1: mag = 1; integer = (man == 0); break; // 1 or 1.5
            case 2: mag = (man == 0) ? 2 : 3; break;      // 2 or 3
            case 3: mag = (man == 0) ? 4 : 6; break;      // 4 or 6
            }
            if (!integer) {
                accepted[nib] = false;
                value[nib] = 0;
                continue;
            }
            if (sign && mag == 0) { // negative zero: rejected
                accepted[nib] = false;
                value[nib] = 0;
                continue;
            }
            accepted[nib] = true;
            value[nib] = static_cast<int8_t>(sign ? -mag : mag);
        }
    }
};
constexpr MantissaTable kMantissaTable{};

// Compile-time proof that the bijection is exactly 11 accepted / 5 rejected
// onto M11, with the specified holes.
constexpr int CountAccepted()
{
    int c = 0;
    for (bool a : kMantissaTable.accepted) c += a ? 1 : 0;
    return c;
}
static_assert(CountAccepted() == 11, "E2M1 bijection must accept exactly 11 of 16 codes");
static_assert(!kMantissaTable.accepted[1] && !kMantissaTable.accepted[3] &&
                  !kMantissaTable.accepted[8] && !kMantissaTable.accepted[9] &&
                  !kMantissaTable.accepted[11],
              "rejected codes must be exactly {0.5,1.5,-0}: nibbles 1,3,8,9,11");

} // namespace

int8_t SampleMantissaNibble(uint8_t nibble, bool& accepted)
{
    const uint8_t n = nibble & 0x0F;
    accepted = kMantissaTable.accepted[n];
    return kMantissaTable.value[n];
}

void ExpandMantissaStream(const uint256& seed, size_t count, int8_t* out)
{
    // Wide counter-mode SHA-256 XOF; one 4-bit nibble per element in stream
    // order (low nibble of each keystream byte first, then high nibble),
    // E2M1-rejection-sampled into M11. Acceptance 11/16 (~5.82 bits/element).
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

    size_t filled = 0;
    uint64_t block = 0;
    while (filled < count) {
        CSHA256 hasher;
        hasher.Write(seed_bytes, sizeof(seed_bytes));
        hasher.Write(&kMantissaStreamDomain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));

        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);

        for (size_t i = 0; i < CSHA256::OUTPUT_SIZE && filled < count; ++i) {
            const uint8_t nibs[2] = {static_cast<uint8_t>(hash[i] & 0x0F),
                                     static_cast<uint8_t>((hash[i] >> 4) & 0x0F)};
            for (uint8_t nib : nibs) {
                bool accepted = false;
                const int8_t mu = SampleMantissaNibble(nib, accepted);
                if (accepted) {
                    out[filled++] = mu;
                    if (filled == count) break;
                }
            }
        }
        ++block;
    }
}

void ExpandMantissaStreamPortable(const uint256& seed, size_t count, int8_t* out)
{
    // Two-pass schedule (device-portable):
    //   1) Emit SHA-256 counter blocks; count accepted nibbles per block.
    //   2) If the prefix sum is short, extend with more blocks (deterministic).
    //   3) Fill `out` in the same low-then-high nibble order as ExpandMantissaStream.
    // Result MUST be byte-identical to ExpandMantissaStream.
    if (count == 0) return;
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

    std::vector<std::array<uint8_t, CSHA256::OUTPUT_SIZE>> blocks;
    std::vector<uint32_t> accept_per_block;
    size_t accepted_total = 0;
    uint64_t block = 0;
    while (accepted_total < count) {
        CSHA256 hasher;
        hasher.Write(seed_bytes, sizeof(seed_bytes));
        hasher.Write(&kMantissaStreamDomain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));
        std::array<uint8_t, CSHA256::OUTPUT_SIZE> hash{};
        hasher.Finalize(hash.data());

        uint32_t acc = 0;
        for (size_t i = 0; i < CSHA256::OUTPUT_SIZE; ++i) {
            for (uint8_t shift : {0, 4}) {
                bool accepted = false;
                (void)SampleMantissaNibble(static_cast<uint8_t>((hash[i] >> shift) & 0x0F), accepted);
                if (accepted) ++acc;
            }
        }
        blocks.push_back(hash);
        accept_per_block.push_back(acc);
        accepted_total += acc;
        ++block;
    }

    size_t filled = 0;
    for (size_t b = 0; b < blocks.size() && filled < count; ++b) {
        const auto& hash = blocks[b];
        for (size_t i = 0; i < CSHA256::OUTPUT_SIZE && filled < count; ++i) {
            const uint8_t nibs[2] = {static_cast<uint8_t>(hash[i] & 0x0F),
                                     static_cast<uint8_t>((hash[i] >> 4) & 0x0F)};
            for (uint8_t nib : nibs) {
                bool accepted = false;
                const int8_t mu = SampleMantissaNibble(nib, accepted);
                if (accepted) {
                    out[filled++] = mu;
                    if (filled == count) break;
                }
            }
        }
    }
}

void ExpandScaleStream(const uint256& seed, size_t count, uint8_t* out)
{
    // Wide counter-mode SHA-256 XOF; 2 bits per E8M0 exponent code, 4 codes
    // per keystream byte from the LSB up, rejection-free -> e in {0,1,2,3}.
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

    size_t filled = 0;
    uint64_t block = 0;
    while (filled < count) {
        CSHA256 hasher;
        hasher.Write(seed_bytes, sizeof(seed_bytes));
        hasher.Write(&kScaleStreamDomain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));

        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);

        for (size_t i = 0; i < CSHA256::OUTPUT_SIZE && filled < count; ++i) {
            for (int shift = 0; shift < 8 && filled < count; shift += 2) {
                out[filled++] = static_cast<uint8_t>((hash[i] >> shift) & 0x03);
            }
        }
        ++block;
    }
}

void ExpandScaleStreamPortable(const uint256& seed, size_t count, uint8_t* out)
{
    // Rejection-free: portable schedule == streaming schedule (same counter order).
    ExpandScaleStream(seed, count, out);
}

uint256 DeriveOperandSeedBMX4C(const CBlockHeader& header, Operand which)
{
    // A: template hash (nonce-independent); B: full header hash (nonce-fresh).
    const uint256 header_hash = (which == Operand::A)
        ? matmul::v4::ComputeTemplateHash(header)
        : matmul::ComputeMatMulHeaderHash(header);
    const uint8_t which_byte = static_cast<uint8_t>(which);
    return DeriveTaggedSeed(kSeedTagV42, sizeof(kSeedTagV42) - 1, header_hash,
                            &which_byte, 1);
}

std::pair<uint256, uint256> DeriveProjectorSeedsBMX4C(const CBlockHeader& header)
{
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(header);
    return {DeriveTaggedSeed(kProjectorUTagV42, sizeof(kProjectorUTagV42) - 1,
                             template_hash, nullptr, 0),
            DeriveTaggedSeed(kProjectorVTagV42, sizeof(kProjectorVTagV42) - 1,
                             template_hash, nullptr, 0)};
}

namespace {

// Dequantize mu (in M11, |.| <= 6) by an E8M0 exponent e in {0..3}: a pure
// power-of-two shift, |result| <= 48 < 128 so it fits int8. E8M0 exactness:
// the scale application never touches a mantissa bit (design §4.3-(3)).
inline int8_t Dequant(int8_t mu, uint8_t e)
{
    return static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
}

} // namespace

std::vector<int8_t> ExpandOperandA(const uint256& seed, uint32_t n)
{
    const size_t count = static_cast<size_t>(n) * n;
    std::vector<int8_t> mu(count);
    ExpandMantissaStream(seed, count, mu.data());

    const uint32_t nblk = n / kBlockLen; // blocks along columns (contraction)
    std::vector<uint8_t> scale(static_cast<size_t>(n) * nblk); // n x (n/32)
    ExpandScaleStream(seed, scale.size(), scale.data());

    std::vector<int8_t> out(count);
    for (uint32_t i = 0; i < n; ++i) {
        const size_t row = static_cast<size_t>(i) * n;
        const size_t srow = static_cast<size_t>(i) * nblk;
        for (uint32_t k = 0; k < n; ++k) {
            out[row + k] = Dequant(mu[row + k], scale[srow + (k / kBlockLen)]);
        }
    }
    return out;
}

std::vector<int8_t> ExpandOperandB(const uint256& seed, uint32_t n)
{
    const size_t count = static_cast<size_t>(n) * n;
    std::vector<int8_t> mu(count);
    ExpandMantissaStream(seed, count, mu.data());

    const uint32_t nblk = n / kBlockLen; // blocks along rows (contraction)
    std::vector<uint8_t> scale(static_cast<size_t>(nblk) * n); // (n/32) x n
    ExpandScaleStream(seed, scale.size(), scale.data());

    std::vector<int8_t> out(count);
    for (uint32_t k = 0; k < n; ++k) {
        const size_t row = static_cast<size_t>(k) * n;
        const size_t srow = static_cast<size_t>(k / kBlockLen) * n;
        for (uint32_t j = 0; j < n; ++j) {
            out[row + j] = Dequant(mu[row + j], scale[srow + j]);
        }
    }
    return out;
}

std::vector<int8_t> ExpandProjectorBMX4C(const uint256& seed, uint32_t rows, uint32_t cols)
{
    const size_t count = static_cast<size_t>(rows) * cols;
    std::vector<int8_t> out(count);
    ExpandMantissaStream(seed, count, out.data()); // scale-free M11
    return out;
}

bool CheckCombineLimbBoundBMX4C(uint32_t n)
{
    // Remainder-top total-decomposition bound: every P/Q entry |x| <= 288*n
    // must satisfy |x| <= 2^23 - 1 (design §5.2). n <= 29,127.
    static_assert(kCombineLimbs == 4 && kCombineLimbBase == 64,
                  "combine bound assumes 4 balanced base-2^6 digits");
    return static_cast<int64_t>(n) * kProjPerMac <= kCombineMaxAbs;
}

namespace {

// Entrywise 4-digit balanced base-2^6 decomposition with the remainder-top
// rule (design §5.2): the low 3 digits are balanced in [-32,31]; the top
// digit d3 carries the exact remainder in [-32,+32]. UNIQUE and TOTAL for
// every |x| <= 2^23-1 (CheckCombineLimbBoundBMX4C). Each plane is a valid s8
// operand (|digit| <= 32).
void DecomposeLimbPlanesBMX4C(const std::vector<int32_t>& M, std::vector<int8_t>* planes)
{
    for (uint32_t l = 0; l < kCombineLimbs; ++l) {
        planes[l].resize(M.size());
    }
    constexpr int32_t kHalf = kCombineLimbBase / 2; // 32
    for (size_t idx = 0; idx < M.size(); ++idx) {
        int32_t x = M[idx];
        // Low 3 balanced digits: d = ((x + 32) mod 64) - 32 in [-32, 31].
        for (uint32_t l = 0; l < kCombineLimbs - 1; ++l) {
            const int32_t d = ((x + kHalf) & (kCombineLimbBase - 1)) - kHalf;
            planes[l][idx] = static_cast<int8_t>(d);
            x = (x - d) / kCombineLimbBase; // exact: (x - d) is a multiple of 64
        }
        // Remainder-top digit: whatever remains, in [-32, +32] under the bound.
        // CheckCombineLimbBoundBMX4C gates |P|,|Q| <= 288*n <= 2^23-1 via
        // ValidateDimsBMX4C, so x is in [-32, +32] for every consensus-valid
        // entry and this can never fire; it is never reached on the verifier
        // path (SketchFreivalds does not decompose). RELEASE-LIVE HARD GUARD vs
        // a silent high-part drop, NOT a debug-only no-op (F-L4): this project
        // strips -DNDEBUG from every build configuration
        // (cmake/module/ProcessConfigurations.cmake), so the assert is compiled
        // into release builds and aborts (fail-CLOSED) on a violation instead of
        // committing a corrupt top digit. Left as an assert deliberately:
        // DecomposeLimbPlanesBMX4C returns void on the hot combine path, so
        // abort-on-violation is the lower-risk fail-closed choice.
        assert(x >= -kHalf && x <= kHalf &&
               "DecomposeLimbPlanesBMX4C: remainder-top digit out of [-32,+32] "
               "(entry exceeds 2^23-1; CheckCombineLimbBoundBMX4C must gate n)");
        planes[kCombineLimbs - 1][idx] = static_cast<int8_t>(x);
    }
}

} // namespace

std::vector<Fq> ComputeCombineLimbTensorBMX4C(const std::vector<int32_t>& P,
                                              const std::vector<int32_t>& Q,
                                              uint32_t n, uint32_t m)
{
    // 16 limb-pair m*m*n exact s8xs8->s32 GEMMs + one O(m^2) shifted mod-q
    // recombine. As exact integers sum_k P[a][k]*Q[k][c] = sum_ij 64^(i+j)
    // S_ij[a][c], so reducing each S_ij with the canonical 64^(i+j) mod q
    // weight yields the same canonical residue as ComputeCombineModQ. Every
    // limb-pair accumulator |sum_k d_i*d_j| <= n*32*32 = 1024*n = 2^22 at
    // n = 4096 (design §2.4) -- exact in true int32 and on any proven-t=24 unit.
    std::vector<int8_t> p_planes[kCombineLimbs];
    std::vector<int8_t> q_planes[kCombineLimbs];
    DecomposeLimbPlanesBMX4C(P, p_planes);
    DecomposeLimbPlanesBMX4C(Q, q_planes);

    // Canonical weights w_ij = 64^(i+j) mod q. All exponents 6*(i+j) <= 36 < 61,
    // so the weight is the small power of two itself.
    Fq weight[kCombineLimbs][kCombineLimbs];
    for (uint32_t i = 0; i < kCombineLimbs; ++i) {
        for (uint32_t j = 0; j < kCombineLimbs; ++j) {
            weight[i][j] = static_cast<Fq>(1) << (6 * (i + j));
        }
    }

    const size_t out_size = static_cast<size_t>(m) * m;
    std::vector<Fq> Chat(out_size, 0);
    std::vector<int32_t> S(out_size);
    for (uint32_t i = 0; i < kCombineLimbs; ++i) {
        const std::vector<int8_t>& Pi = p_planes[i]; // m x n s8
        for (uint32_t j = 0; j < kCombineLimbs; ++j) {
            const std::vector<int8_t>& Qj = q_planes[j]; // n x m s8
            std::fill(S.begin(), S.end(), 0);
            for (uint32_t a = 0; a < m; ++a) {
                const int8_t* p_row = &Pi[static_cast<size_t>(a) * n];
                int32_t* s_row = &S[static_cast<size_t>(a) * m];
                for (uint32_t k = 0; k < n; ++k) {
                    const int32_t p_ak = p_row[k];
                    if (p_ak == 0) continue; // deterministic skip of zero MACs
                    const int8_t* q_row = &Qj[static_cast<size_t>(k) * m];
                    for (uint32_t c = 0; c < m; ++c) {
                        s_row[c] += p_ak * static_cast<int32_t>(q_row[c]);
                    }
                }
            }
            const Fq w = weight[i][j];
            for (size_t idx = 0; idx < out_size; ++idx) {
                Chat[idx] = int8_field::FqAdd(
                    Chat[idx], int8_field::FqMul(w, int8_field::FqFromSigned(S[idx])));
            }
        }
    }
    return Chat;
}

namespace {

// Build the nine Karatsuba operand planes from four base-2^6 limb planes.
// Layout: [p0, p1, p0+p1, p2, p3, p2+p3, p0+p2, p1+p3, p0+p1+p2+p3].
// Digit sums are bounded by [-128,125] and fit signed INT8 (design note).
void BuildKaratsubaPlanes(const std::vector<int8_t> limbs[kCombineLimbs],
                          std::vector<int8_t> (&planes)[9])
{
    const size_t n = limbs[0].size();
    for (auto& p : planes) p.resize(n);
    for (size_t i = 0; i < n; ++i) {
        const int32_t d0 = limbs[0][i];
        const int32_t d1 = limbs[1][i];
        const int32_t d2 = limbs[2][i];
        const int32_t d3 = limbs[3][i];
        planes[0][i] = static_cast<int8_t>(d0);
        planes[1][i] = static_cast<int8_t>(d1);
        planes[2][i] = static_cast<int8_t>(d0 + d1);
        planes[3][i] = static_cast<int8_t>(d2);
        planes[4][i] = static_cast<int8_t>(d3);
        planes[5][i] = static_cast<int8_t>(d2 + d3);
        planes[6][i] = static_cast<int8_t>(d0 + d2);
        planes[7][i] = static_cast<int8_t>(d1 + d3);
        planes[8][i] = static_cast<int8_t>(d0 + d1 + d2 + d3);
    }
}

// Exact s8xs8->s32 GEMM: C[m x m] += A[m x n] * B[n x m] (row-major).
void GemmS8S32Add(const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                  std::vector<int32_t>& C, uint32_t m, uint32_t n)
{
    for (uint32_t a = 0; a < m; ++a) {
        const int8_t* a_row = &A[static_cast<size_t>(a) * n];
        int32_t* c_row = &C[static_cast<size_t>(a) * m];
        for (uint32_t k = 0; k < n; ++k) {
            const int32_t ak = a_row[k];
            if (ak == 0) continue;
            const int8_t* b_row = &B[static_cast<size_t>(k) * m];
            for (uint32_t c = 0; c < m; ++c) {
                c_row[c] += ak * static_cast<int32_t>(b_row[c]);
            }
        }
    }
}

// Fused M61 epilogue weights for the nine Karatsuba products in BuildKaratsubaPlanes
// order (m00, m11, m01, m22, m33, m23, m02, m13, m03). Derived by expanding the
// two-level Karatsuba reconstruction into Chat = sum_k 64^k * c_k mod q.
void Karatsuba9FqWeights(Fq (&w_out)[9])
{
    const Fq w[7] = {
        static_cast<Fq>(1) << 0,
        static_cast<Fq>(1) << 6,
        static_cast<Fq>(1) << 12,
        static_cast<Fq>(1) << 18,
        static_cast<Fq>(1) << 24,
        static_cast<Fq>(1) << 30,
        static_cast<Fq>(1) << 36,
    };
    auto add = [](Fq a, Fq b) { return int8_field::FqAdd(a, b); };
    auto neg = [](Fq a) { return int8_field::FqNeg(a); };
    // m00: +w0 -w1 -w2 +w3
    w_out[0] = add(add(w[0], neg(w[1])), add(neg(w[2]), w[3]));
    // m11: -w1 +w2 +w3 -w4
    w_out[1] = add(add(neg(w[1]), w[2]), add(w[3], neg(w[4])));
    // m01: +w1 -w3
    w_out[2] = add(w[1], neg(w[3]));
    // m22: -w2 +w3 +w4 -w5
    w_out[3] = add(add(neg(w[2]), w[3]), add(w[4], neg(w[5])));
    // m33: +w3 -w4 -w5 +w6
    w_out[4] = add(add(w[3], neg(w[4])), add(neg(w[5]), w[6]));
    // m23: -w3 +w5
    w_out[5] = add(neg(w[3]), w[5]);
    // m02: +w2 -w3
    w_out[6] = add(w[2], neg(w[3]));
    // m13: -w3 +w4
    w_out[7] = add(neg(w[3]), w[4]);
    // m03: +w3
    w_out[8] = w[3];
}

// Pair the nine Karatsuba left/right plane indices (into BuildKaratsubaPlanes).
// Products use matching indices: (0,0)=m00 ... (8,8)=m03.

// Five balanced base-32 digits in [-16,15] (exact E4M3 integer alphabet).
constexpr uint32_t kFp8Limbs = 5;
constexpr int32_t kFp8Base = 32;
constexpr int32_t kFp8Half = 16;

void DecomposeFp8FiveLimbPlanes(const std::vector<int32_t>& M, std::vector<int8_t>* planes)
{
    for (uint32_t l = 0; l < kFp8Limbs; ++l) planes[l].resize(M.size());
    for (size_t idx = 0; idx < M.size(); ++idx) {
        int32_t x = M[idx];
        for (uint32_t l = 0; l < kFp8Limbs - 1; ++l) {
            const int32_t d = ((x + kFp8Half) & (kFp8Base - 1)) - kFp8Half;
            planes[l][idx] = static_cast<int8_t>(d);
            x = (x - d) / kFp8Base;
        }
        // Top digit: under |x| <= 288*n <= 2^23-1, five base-32 digits cover
        // |x| < 32^5/2 = 2^24, so the remainder is in [-16,16] with margin.
        assert(x >= -kFp8Half && x <= kFp8Half);
        planes[kFp8Limbs - 1][idx] = static_cast<int8_t>(x);
    }
}

} // namespace

std::vector<Fq> ComputeCombineKaratsuba9BMX4C(const std::vector<int32_t>& P,
                                              const std::vector<int32_t>& Q,
                                              uint32_t n, uint32_t m)
{
    std::vector<int8_t> p_limbs[kCombineLimbs];
    std::vector<int8_t> q_limbs[kCombineLimbs];
    DecomposeLimbPlanesBMX4C(P, p_limbs);
    DecomposeLimbPlanesBMX4C(Q, q_limbs);

    std::vector<int8_t> p_planes[9];
    std::vector<int8_t> q_planes[9];
    BuildKaratsubaPlanes(p_limbs, p_planes);
    BuildKaratsubaPlanes(q_limbs, q_planes);

    Fq weights[9];
    Karatsuba9FqWeights(weights);

    const size_t out_size = static_cast<size_t>(m) * m;
    std::vector<Fq> Chat(out_size, 0);
    std::vector<int32_t> S(out_size);
    for (uint32_t r = 0; r < 9; ++r) {
        std::fill(S.begin(), S.end(), 0);
        GemmS8S32Add(p_planes[r], q_planes[r], S, m, n);
        const Fq w = weights[r];
        for (size_t idx = 0; idx < out_size; ++idx) {
            Chat[idx] = int8_field::FqAdd(
                Chat[idx], int8_field::FqMul(w, int8_field::FqFromSigned(S[idx])));
        }
    }
    return Chat;
}

std::vector<Fq> ComputeCombineFp8FiveLimbBMX4C(const std::vector<int32_t>& P,
                                               const std::vector<int32_t>& Q,
                                               uint32_t n, uint32_t m)
{
    std::vector<int8_t> p_planes[kFp8Limbs];
    std::vector<int8_t> q_planes[kFp8Limbs];
    DecomposeFp8FiveLimbPlanes(P, p_planes);
    DecomposeFp8FiveLimbPlanes(Q, q_planes);

    Fq weight[kFp8Limbs][kFp8Limbs];
    for (uint32_t i = 0; i < kFp8Limbs; ++i) {
        for (uint32_t j = 0; j < kFp8Limbs; ++j) {
            // 32^(i+j) = 2^(5(i+j)); exponent <= 40 < 61 so the weight is exact.
            weight[i][j] = static_cast<Fq>(1) << (5 * (i + j));
        }
    }

    const size_t out_size = static_cast<size_t>(m) * m;
    std::vector<Fq> Chat(out_size, 0);
    std::vector<int32_t> S(out_size);
    for (uint32_t i = 0; i < kFp8Limbs; ++i) {
        for (uint32_t j = 0; j < kFp8Limbs; ++j) {
            std::fill(S.begin(), S.end(), 0);
            GemmS8S32Add(p_planes[i], q_planes[j], S, m, n);
            const Fq w = weight[i][j];
            for (size_t idx = 0; idx < out_size; ++idx) {
                Chat[idx] = int8_field::FqAdd(
                    Chat[idx], int8_field::FqMul(w, int8_field::FqFromSigned(S[idx])));
            }
        }
    }
    return Chat;
}

std::vector<int32_t> ComputeProjectedLeftScalePartitionedBMX4C(
    const std::vector<int8_t>& U, const std::vector<int8_t>& mu_a,
    const std::vector<uint8_t>& scale_a, uint32_t n, uint32_t m)
{
    // P[a][k] = sum_i U[a][i] * mu_a[i][k] * 2^{e(i, k/32)}.
    // For each column-block kb, partition rows i by e(i, kb) and evaluate four
    // reduced-K GEMMs whose K's sum to n (not 4n).
    const uint32_t nblk = n / kBlockLen;
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 0);
    std::vector<uint32_t> bucket[kNumScaleCodes];
    std::vector<int8_t> U_e;
    std::vector<int8_t> A_e;

    for (uint32_t kb = 0; kb < nblk; ++kb) {
        for (auto& b : bucket) b.clear();
        for (uint32_t i = 0; i < n; ++i) {
            const uint8_t e = scale_a[static_cast<size_t>(i) * nblk + kb];
            bucket[e].push_back(i);
        }
        for (uint32_t e = 0; e < kNumScaleCodes; ++e) {
            const uint32_t Ke = static_cast<uint32_t>(bucket[e].size());
            if (Ke == 0) continue;
            U_e.resize(static_cast<size_t>(m) * Ke);
            A_e.resize(static_cast<size_t>(Ke) * kBlockLen);
            for (uint32_t t = 0; t < Ke; ++t) {
                const uint32_t i = bucket[e][t];
                for (uint32_t a = 0; a < m; ++a) {
                    U_e[static_cast<size_t>(a) * Ke + t] = U[static_cast<size_t>(a) * n + i];
                }
                for (uint32_t c = 0; c < kBlockLen; ++c) {
                    A_e[static_cast<size_t>(t) * kBlockLen + c] =
                        mu_a[static_cast<size_t>(i) * n + kb * kBlockLen + c];
                }
            }
            // Partial = U_e[m x Ke] * A_e[Ke x 32], then P += partial << e.
            for (uint32_t a = 0; a < m; ++a) {
                for (uint32_t c = 0; c < kBlockLen; ++c) {
                    int32_t acc = 0;
                    for (uint32_t t = 0; t < Ke; ++t) {
                        acc += static_cast<int32_t>(U_e[static_cast<size_t>(a) * Ke + t]) *
                               static_cast<int32_t>(A_e[static_cast<size_t>(t) * kBlockLen + c]);
                    }
                    P[static_cast<size_t>(a) * n + kb * kBlockLen + c] += acc * (1 << e);
                }
            }
        }
    }
    return P;
}

std::vector<int32_t> ComputeProjectedRightScalePartitionedBMX4C(
    const std::vector<int8_t>& mu_b, const std::vector<uint8_t>& scale_b,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m)
{
    // Q[k][c] = sum_j mu_b[k][j] * 2^{e(k/32, j)} * V[j][c].
    // For each 32-row block of B, partition columns j by committed scale e.
    const uint32_t nblk = n / kBlockLen;
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 0);
    std::vector<uint32_t> bucket[kNumScaleCodes];
    std::vector<int8_t> B_e;
    std::vector<int8_t> V_e;

    for (uint32_t rb = 0; rb < nblk; ++rb) {
        for (auto& b : bucket) b.clear();
        const size_t srow = static_cast<size_t>(rb) * n;
        for (uint32_t j = 0; j < n; ++j) {
            bucket[scale_b[srow + j]].push_back(j);
        }
        for (uint32_t e = 0; e < kNumScaleCodes; ++e) {
            const uint32_t Ke = static_cast<uint32_t>(bucket[e].size());
            if (Ke == 0) continue;
            B_e.resize(static_cast<size_t>(kBlockLen) * Ke);
            V_e.resize(static_cast<size_t>(Ke) * m);
            for (uint32_t t = 0; t < Ke; ++t) {
                const uint32_t j = bucket[e][t];
                for (uint32_t r = 0; r < kBlockLen; ++r) {
                    B_e[static_cast<size_t>(r) * Ke + t] =
                        mu_b[static_cast<size_t>(rb * kBlockLen + r) * n + j];
                }
                for (uint32_t c = 0; c < m; ++c) {
                    V_e[static_cast<size_t>(t) * m + c] = V[static_cast<size_t>(j) * m + c];
                }
            }
            for (uint32_t r = 0; r < kBlockLen; ++r) {
                for (uint32_t c = 0; c < m; ++c) {
                    int32_t acc = 0;
                    for (uint32_t t = 0; t < Ke; ++t) {
                        acc += static_cast<int32_t>(B_e[static_cast<size_t>(r) * Ke + t]) *
                               static_cast<int32_t>(V_e[static_cast<size_t>(t) * m + c]);
                    }
                    Q[static_cast<size_t>(rb * kBlockLen + r) * m + c] += acc * (1 << e);
                }
            }
        }
    }
    return Q;
}

ExactAccelPlan PlanExactAccelLanes(std::string_view device_class)
{
    ExactAccelPlan plan;
    // Default: H200/Hopper-class INT8 projection + Karatsuba-9 combine.
    plan.projection = ProjectionLane::CanonicalInt8;
    plan.combine = CombineLane::Karatsuba9Int8;

    auto eq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            const char ca = (a[i] >= 'A' && a[i] <= 'Z') ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
            const char cb = (b[i] >= 'A' && b[i] <= 'Z') ? static_cast<char>(b[i] - 'A' + 'a') : b[i];
            if (ca != cb) return false;
        }
        return true;
    };

    if (eq(device_class, "b200") || eq(device_class, "blackwell") || eq(device_class, "sm100") ||
        eq(device_class, "sm120") || eq(device_class, "5090") || eq(device_class, "mi350") ||
        eq(device_class, "mi355")) {
        plan.projection = ProjectionLane::ScalePartitionedMxfp4;
        plan.combine = CombineLane::Karatsuba9Int8;
    } else if (eq(device_class, "rubin") || eq(device_class, "rubin-class")) {
        plan.projection = ProjectionLane::ExactFp8;
        plan.combine = CombineLane::ExactFp8FiveLimb;
    } else if (eq(device_class, "cpu") || eq(device_class, "scalar")) {
        plan.projection = ProjectionLane::CanonicalInt8;
        plan.combine = CombineLane::CanonicalInteger;
    }
    return plan;
}

bool ValidateDimsBMX4(uint32_t n, uint32_t b, uint32_t& m_out)
{
    // b-PARAMETRIC BMX4 validator (design §4.2): the structural gates are
    // IDENTICAL across every BMX4 encoding profile — n % 32 == 0 (E8M0 block
    // scales), CheckCombineLimbBoundBMX4C(n) (288·n <= 2^23-1, m-independent),
    // n > 0, b | n, and the exact-int32 accumulation bound. Only the tile b
    // differs between profiles (C: b = kTileB = 4; D: b = kTileBMX4D = 2), so a
    // single routine serves both.
    if ((n % kBlockLen) != 0) return false;      // E8M0 block scales
    if (!CheckCombineLimbBoundBMX4C(n)) return false;
    return matmul::v4::ValidateDims(n, b, m_out); // n>0, b|n, s32 accum bound
}

bool ValidateDimsBMX4C(uint32_t n, uint32_t b, uint32_t& m_out)
{
    return ValidateDimsBMX4(n, b, m_out); // C tile (b = kTileB = 4) passed by caller
}

bool ComputeDigestBMX4C(const CBlockHeader& header, uint32_t n,
                        uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header); // UNCHANGED
    const uint256 seed_a = DeriveOperandSeedBMX4C(header, Operand::A);
    const uint256 seed_b = DeriveOperandSeedBMX4C(header, Operand::B);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4C(header);

    const std::vector<int8_t> Ahat = ExpandOperandA(seed_a, n);
    const std::vector<int8_t> Bhat = ExpandOperandB(seed_b, n);
    const std::vector<int8_t> U = ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = ExpandProjectorBMX4C(seed_v, n, m);

    // Optimal factoring Chat = (U*Ahat)(Bhat*V), never forming C. Reuses the
    // v4 projection + direct mod-q combine (byte-identical to the base-2^6
    // limb path and to the full-C U*C*V path).
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, Ahat, n, m);
    const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(Bhat, V, n, m);
    const std::vector<Fq> Chat = matmul::v4::ComputeCombineModQ(P, Q, n, m);

    payload_out = matmul::v4::SerializeSketch(Chat);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
    return true;
}

bool VerifySketchBMX4C(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                       const std::vector<unsigned char>& payload, uint256& digest_out)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        return false;
    }
    // Fail-closed on rounds == 0 (F-L3): matmul::v4::SketchFreivalds returns true
    // unconditionally when rounds == 0, so a misconfigured 0-round verify would
    // otherwise become a no-op accept. rounds is a fixed consensus param (never
    // 0, never attacker-controlled), but the verifier MUST reject here to match
    // ComputeDigestBMX4C's guard and the ENC-S8 VerifySketch.
    if (rounds == 0) {
        return false;
    }

    std::vector<Fq> sketch;
    if (!matmul::v4::ParseSketch(payload, m, sketch)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload);
    if (digest_out != header.matmul_digest) {
        return false;
    }

    // Regenerate the dequantized operands; |Ahat|,|Bhat| <= 48 and |U|,|V| <= 6
    // all fit int8, so the UNCHANGED SketchFreivalds verifier consumes them as
    // exact integers -- it is compute-path-agnostic (design §3).
    const uint256 seed_a = DeriveOperandSeedBMX4C(header, Operand::A);
    const uint256 seed_b = DeriveOperandSeedBMX4C(header, Operand::B);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4C(header);
    const std::vector<int8_t> Ahat = ExpandOperandA(seed_a, n);
    const std::vector<int8_t> Bhat = ExpandOperandB(seed_b, n);
    const std::vector<int8_t> U = ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = ExpandProjectorBMX4C(seed_v, n, m);

    return matmul::v4::SketchFreivalds(Ahat, Bhat, U, V, sketch, sigma, payload,
                                       n, m, rounds);
}

// ---------------------------------------------------------------------------
// ENC-BMX4C-D / v4.2-D reference routines — LIBRARY CODE ONLY, NOT a consensus
// path. There is NO consensus caller in the tree: GetMatMulEncodingProfile only
// returns ENC_S8/ENC_BMX4C, no IsBMX4CDActive predicate exists, and no
// pow.cpp verify/solve path dispatches here. enum value ENC_BMX4CD (3) is
// RETIRED/RESERVED (consensus/params.h).
//
// SUPERSEDED HISTORY (do NOT read as current wiring): D was briefly reinstated
// as a live consensus profile (solver-evolution Stage 1) after an on-silicon
// per-card measurement, carried as a 32 MiB SEGREGATED PRUNABLE PROOF (design
// §3, Stage 2 relay). v4.4 ENC-DR then DELETED the entire segregated-proof
// subsystem and made a deeper commit a storage-free digest-only parameter
// retarget rather than a distinct profile — so the "REAL consensus code path"
// and "getmatmulproof/matmulproof relay" that older revisions of this comment
// described NO LONGER EXIST. See doc/btx-matmul-v4.2-solver-evolution-design.md.
// The b=2 operand math below stays valid as reference/library code.
// ---------------------------------------------------------------------------
// ENC-BMX4C-D (deeper-commit profile): the ENC-BMX4C construction with b = 2
// (m = n/2), so the sketch commits 4x more of the exact-integer product C and
// the enforced per-nonce tensor work is ~3.6x (limb-tensor combine 16*n*m^2,
// quadratic in m). EVERY operand-encoding primitive is REUSED UNCHANGED
// (ExpandOperandA/B, ExpandProjectorBMX4C, ComputeProjectedLeft/Right,
// ComputeCombineModQ, SerializeSketch, ComputeSketchDigest, SketchFreivalds) --
// only the sketch rank m and the domain tags differ. The accumulator bounds
// (2304*n, 288*n, 1024*n) are m-INDEPENDENT, so ENC-BMX4C-D preserves M-t24
// determinism byte-for-byte. See matmul_v4_bmx4.h and
// doc/btx-matmul-v4.2-compute-bound-redesign.md.
// ---------------------------------------------------------------------------

uint256 DeriveOperandSeedBMX4D(const CBlockHeader& header, Operand which)
{
    // A: template hash (nonce-independent); B: full header hash (nonce-fresh).
    const uint256 header_hash = (which == Operand::A)
        ? matmul::v4::ComputeTemplateHash(header)
        : matmul::ComputeMatMulHeaderHash(header);
    const uint8_t which_byte = static_cast<uint8_t>(which);
    return DeriveTaggedSeed(kSeedTagV42D, sizeof(kSeedTagV42D) - 1, header_hash,
                            &which_byte, 1);
}

std::pair<uint256, uint256> DeriveProjectorSeedsBMX4D(const CBlockHeader& header)
{
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(header);
    return {DeriveTaggedSeed(kProjectorUTagV42D, sizeof(kProjectorUTagV42D) - 1,
                             template_hash, nullptr, 0),
            DeriveTaggedSeed(kProjectorVTagV42D, sizeof(kProjectorVTagV42D) - 1,
                             template_hash, nullptr, 0)};
}

bool ValidateDimsBMX4D(uint32_t n, uint32_t& m_out)
{
    return ValidateDimsBMX4(n, kTileBMX4D, m_out); // D tile (b = kTileBMX4D = 2)
}

bool ComputeDigestBMX4D(const CBlockHeader& header, uint32_t n,
                        uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4D(n, m)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header); // UNCHANGED
    const uint256 seed_a = DeriveOperandSeedBMX4D(header, Operand::A);
    const uint256 seed_b = DeriveOperandSeedBMX4D(header, Operand::B);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4D(header);

    const std::vector<int8_t> Ahat = ExpandOperandA(seed_a, n);
    const std::vector<int8_t> Bhat = ExpandOperandB(seed_b, n);
    const std::vector<int8_t> U = ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = ExpandProjectorBMX4C(seed_v, n, m);

    // Optimal factoring Chat = (U*Ahat)(Bhat*V), never forming C -- byte-
    // identical to the full-C U*C*V path and to the base-2^6 limb-tensor path
    // at m = n/2. The larger m is exactly what the miner cannot avoid
    // committing, which is what raises the enforced tensor work.
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, Ahat, n, m);
    const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(Bhat, V, n, m);
    const std::vector<Fq> Chat = matmul::v4::ComputeCombineModQ(P, Q, n, m);

    payload_out = matmul::v4::SerializeSketch(Chat);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
    return true;
}

bool VerifySketchBMX4D(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                       const std::vector<unsigned char>& payload, uint256& digest_out)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4D(n, m)) {
        return false;
    }
    if (rounds == 0) { // fail-closed, mirroring VerifySketchBMX4C (F-L3)
        return false;
    }

    std::vector<Fq> sketch;
    if (!matmul::v4::ParseSketch(payload, m, sketch)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload);
    if (digest_out != header.matmul_digest) {
        return false;
    }

    const uint256 seed_a = DeriveOperandSeedBMX4D(header, Operand::A);
    const uint256 seed_b = DeriveOperandSeedBMX4D(header, Operand::B);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4D(header);
    const std::vector<int8_t> Ahat = ExpandOperandA(seed_a, n);
    const std::vector<int8_t> Bhat = ExpandOperandB(seed_b, n);
    const std::vector<int8_t> U = ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = ExpandProjectorBMX4C(seed_v, n, m);

    return matmul::v4::SketchFreivalds(Ahat, Bhat, U, V, sketch, sigma, payload,
                                       n, m, rounds);
}

} // namespace matmul::v4::bmx4
