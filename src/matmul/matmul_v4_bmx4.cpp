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
#include <cstdint>
#include <utility>

namespace matmul::v4::bmx4 {
namespace {

// V4.2 domain-separation tags (design §2.3). Distinct from the v4.1 "_V4"
// tags so the two encoding profiles are cryptographically independent objects.
constexpr char kSeedTagV42[] = "BTX_MATMUL_SEED_V42";
constexpr char kProjectorUTagV42[] = "BTX_MATMUL_V42_SKETCH_U";
constexpr char kProjectorVTagV42[] = "BTX_MATMUL_V42_SKETCH_V";

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

bool ValidateDimsBMX4C(uint32_t n, uint32_t b, uint32_t& m_out)
{
    if ((n % kBlockLen) != 0) return false;      // E8M0 block scales
    if (!CheckCombineLimbBoundBMX4C(n)) return false;
    return matmul::v4::ValidateDims(n, b, m_out); // n>0, b|n, s32 accum bound
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

} // namespace matmul::v4::bmx4
