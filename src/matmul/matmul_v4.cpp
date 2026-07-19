// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4.h>

#include <matmul/matmul_pow.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <cstdint>

namespace matmul::v4 {
namespace {

using int8_field::Fq;
using int8_field::kFieldPrime;

// Domain-separation tags (§A.2, §E.1, §D.1). Distinct byte strings keep every
// derived object in an independent PRF domain.
constexpr char kSeedTag[] = "BTX_MATMUL_SEED_V4";
constexpr char kSketchDigestTag[] = "BTX_MATMUL_V4";
constexpr char kProjectorUTag[] = "BTX_MATMUL_V4_SKETCH_U";
constexpr char kProjectorVTag[] = "BTX_MATMUL_V4_SKETCH_V";
constexpr char kFiatShamirTag[] = "BTX_MATMUL_V4_FS";

uint256 Sha256d(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

// Precompute the canonical F_q image of a balanced-s8 matrix (§D.3): every
// entry lifted once so the hot Freivalds/sketch loops avoid re-reducing.
std::vector<Fq> LiftS8ToFq(const std::vector<int8_t>& m)
{
    std::vector<Fq> out(m.size());
    for (size_t i = 0; i < m.size(); ++i) {
        out[i] = int8_field::FqFromSigned(static_cast<int64_t>(m[i]));
    }
    return out;
}

} // namespace

bool ValidateDims(uint32_t n, uint32_t b, uint32_t& m_out)
{
    if (n == 0 || b == 0) return false;
    if (n > int8_field::kMaxHeaderDim) return false;
    if ((n % b) != 0) return false;
    if (!int8_field::CheckAccumulationBound(n)) return false;
    // Defense-in-depth / symmetry with ValidateDimsBMX4 (which gates
    // CheckCombineLimbBoundBMX4C): also enforce the base-2^7 limb-decomposition
    // totality bound here so a future S8 dimension retarget cannot silently
    // outrun DecomposeLimbPlanes (it discards any remainder past 4 digits).
    // Fails CLOSED (return false, matching this validator's style) on violation
    // rather than asserting. Rejects no currently-valid dimension: the bound is
    // 15,625*n <= 133,160,895, i.e. n <= 8522, which covers the whole documented
    // 4096..8192 window (n=4096: 15,625*4096 = 64,000,000 <= 133,160,895).
    if (!CheckCombineLimbBound(n)) return false;
    m_out = n / b;
    return true;
}

uint256 DeriveSigma(const CBlockHeader& header)
{
    // sigma = SHA256d(full header) -- reuse the v3 rule so nNonce64 and every
    // other header field are bound (§A.2, invariant I7).
    return matmul::DeriveSigma(header);
}

uint256 ComputeTemplateHash(const CBlockHeader& header)
{
    // §A.2 v4.1: the template projection zeroes EVERY nonce-dependent header
    // field before hashing. nNonce64/nNonce are the nonce itself; seed_a and
    // seed_b are nonce-DERIVED under the §H.4 rule (their preimage includes
    // nNonce64), so leaving them in would make the "template" hash vary per
    // nonce and silently defeat the whole §K.2b amortization. They are safe
    // to drop here: consensus pins header.seed_a/seed_b to their §H.4
    // derivation independently, and sigma / seed_B still bind them in full.
    // Remaining bound fields: nVersion, hashPrevBlock, hashMerkleRoot, nTime,
    // nBits, matmul_dim — so the template hash exists only once the parent
    // block and the concrete template exist (no pre-mining).
    CBlockHeader template_header{header};
    template_header.nNonce64 = 0;
    template_header.nNonce = 0;
    template_header.seed_a.SetNull();
    template_header.seed_b.SetNull();
    return matmul::ComputeMatMulHeaderHash(template_header);
}

uint256 DeriveOperandSeed(const CBlockHeader& header, Operand which)
{
    // Bind the header via the canonical v3 header hash, then domain-separate
    // by operand byte 'A'/'B' (§A.2, v4.1 revision — see matmul_v4.h):
    //
    //   B: full header hash (nNonce64 + §H.4 seeds included) — nonce-fresh.
    //      The per-nonce marginal work (expand B, B*V, combine, digest) hangs
    //      off this seed and is what difficulty prices (invariant I1').
    //   A: TEMPLATE hash (ComputeTemplateHash) — constant across the nonce
    //      sweep, so a miner expands A (and computes P = U*A) once per
    //      template (§K.2b batched-sketch profile). Still parent/template-
    //      bound: nothing is precomputable before the template exists.
    const uint256 header_hash = (which == Operand::A)
        ? ComputeTemplateHash(header)
        : matmul::ComputeMatMulHeaderHash(header);

    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kSeedTag), sizeof(kSeedTag) - 1);
    hasher.Write(header_hash.data(), uint256::size());
    const uint8_t which_byte = static_cast<uint8_t>(which);
    hasher.Write(&which_byte, 1);

    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

std::pair<uint256, uint256> DeriveProjectorSeeds(const CBlockHeader& header)
{
    // §A.2 v4.1 (invariant I1', supersedes v4.0's I7): U and V are TEMPLATE-
    // scoped — derived from the template hash, not from sigma — so P = U*A is
    // computable once per template and the per-nonce combines batch into one
    // dense GEMM (§K.2b). The Fiat-Shamir Freivalds challenges stay nonce-
    // fresh (DeriveChallengeSeed binds sigma and the payload), so verifier
    // soundness is unchanged. See spec §C I1' for the anti-amortization
    // relaxation this entails and its needs-external-review status.
    const uint256 template_hash = ComputeTemplateHash(header);
    auto derive = [&template_hash](const char* tag, size_t taglen) {
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
        hasher.Write(template_hash.data(), uint256::size());
        uint8_t out[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(out);
        return uint256{Span<const unsigned char>{out, sizeof(out)}};
    };
    return {derive(kProjectorUTag, sizeof(kProjectorUTag) - 1),
            derive(kProjectorVTag, sizeof(kProjectorVTag) - 1)};
}

std::vector<int8_t> ExpandOperand(const uint256& seed, uint32_t n)
{
    // Wide counter-mode XOF (§A.2, Appendix C-12): ~31.4 elements per SHA-256
    // compression instead of the retired one-hash-per-element oracle, so the
    // per-nonce hash cost stays subdominant to the INT8 GEMM (PR #89 review).
    const size_t count = static_cast<size_t>(n) * n;
    std::vector<int8_t> out(count);
    int8_field::ExpandBalancedS8Stream(seed, count, out.data());
    return out;
}

std::vector<int8_t> ExpandProjector(const uint256& seed, uint32_t rows, uint32_t cols)
{
    const size_t count = static_cast<size_t>(rows) * cols;
    std::vector<int8_t> out(count);
    int8_field::ExpandBalancedS8Stream(seed, count, out.data());
    return out;
}

std::vector<int32_t> ComputeExactProduct(const std::vector<int8_t>& A,
                                         const std::vector<int8_t>& B,
                                         uint32_t n)
{
    // Reference miner path: exact dense s8xs8->s32 GEMM, C = A*B (§A.3/§B.4).
    // The optimal sketch miner would instead evaluate Chat = (U*A)(B*V)
    // directly (§E.3); forming C here yields the identical committed Chat and
    // keeps the reference maximally simple and auditable.
    std::vector<int32_t> C(static_cast<size_t>(n) * n, 0);
    for (uint32_t i = 0; i < n; ++i) {
        const int8_t* a_row = &A[static_cast<size_t>(i) * n];
        int32_t* c_row = &C[static_cast<size_t>(i) * n];
        for (uint32_t k = 0; k < n; ++k) {
            const int32_t a_ik = a_row[k];
            if (a_ik == 0) continue; // deterministic skip of zero MACs
            const int8_t* b_row = &B[static_cast<size_t>(k) * n];
            for (uint32_t j = 0; j < n; ++j) {
                c_row[j] += a_ik * static_cast<int32_t>(b_row[j]);
            }
        }
    }
    return C;
}

std::vector<Fq> ComputeSketch(const std::vector<int8_t>& U,
                              const std::vector<int32_t>& C,
                              const std::vector<int8_t>& V,
                              uint32_t n, uint32_t m)
{
    // Chat = U * C * V over F_q (§E.1). U is m x n, C is n x n exact int32,
    // V is n x m. Computed as T = U*C (m x n) then Chat = T*V (m x m); the
    // small m x m stage stays in exact 64-bit / mod-q ALU arithmetic (§0.7 U,V
    // note, §B.6).
    const std::vector<Fq> Uq = LiftS8ToFq(U);
    const std::vector<Fq> Vq = LiftS8ToFq(V);

    std::vector<Fq> T(static_cast<size_t>(m) * n, 0);
    for (uint32_t a = 0; a < m; ++a) {
        Fq* t_row = &T[static_cast<size_t>(a) * n];
        const Fq* u_row = &Uq[static_cast<size_t>(a) * n];
        for (uint32_t i = 0; i < n; ++i) {
            const Fq u_ai = u_row[i];
            if (u_ai == 0) continue;
            const int32_t* c_row = &C[static_cast<size_t>(i) * n];
            for (uint32_t j = 0; j < n; ++j) {
                t_row[j] = int8_field::FqAdd(t_row[j],
                                             int8_field::FqMul(u_ai, int8_field::FqFromInt32(c_row[j])));
            }
        }
    }

    std::vector<Fq> Chat(static_cast<size_t>(m) * m, 0);
    for (uint32_t a = 0; a < m; ++a) {
        const Fq* t_row = &T[static_cast<size_t>(a) * n];
        Fq* chat_row = &Chat[static_cast<size_t>(a) * m];
        for (uint32_t j = 0; j < n; ++j) {
            const Fq t_aj = t_row[j];
            if (t_aj == 0) continue;
            const Fq* v_row = &Vq[static_cast<size_t>(j) * m];
            for (uint32_t c = 0; c < m; ++c) {
                chat_row[c] = int8_field::FqAdd(chat_row[c], int8_field::FqMul(t_aj, v_row[c]));
            }
        }
    }
    return Chat;
}

std::vector<int32_t> ComputeProjectedLeft(const std::vector<int8_t>& U,
                                          const std::vector<int8_t>& A,
                                          uint32_t n, uint32_t m)
{
    // P = U * A, exact s8xs8->s32, m x n. Each entry P[a][k] = sum_i U[a][i]*A[i][k]
    // is a length-n balanced-s8 dot: |P[a][k]| <= n*125^2 < 2^30, exact in int32
    // (same accumulation bound as C, already validated by CheckAccumulationBound).
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 0);
    for (uint32_t a = 0; a < m; ++a) {
        const int8_t* u_row = &U[static_cast<size_t>(a) * n];
        int32_t* p_row = &P[static_cast<size_t>(a) * n];
        for (uint32_t i = 0; i < n; ++i) {
            const int32_t u_ai = u_row[i];
            if (u_ai == 0) continue; // deterministic skip of zero MACs
            const int8_t* a_row = &A[static_cast<size_t>(i) * n];
            for (uint32_t k = 0; k < n; ++k) {
                p_row[k] += u_ai * static_cast<int32_t>(a_row[k]);
            }
        }
    }
    return P;
}

std::vector<int32_t> ComputeProjectedRight(const std::vector<int8_t>& B,
                                           const std::vector<int8_t>& V,
                                           uint32_t n, uint32_t m)
{
    // Q = B * V, exact s8xs8->s32, n x m. Each entry Q[k][c] = sum_j B[k][j]*V[j][c]
    // is a length-n balanced-s8 dot, same |.| < 2^30 bound as P.
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 0);
    for (uint32_t k = 0; k < n; ++k) {
        const int8_t* b_row = &B[static_cast<size_t>(k) * n];
        int32_t* q_row = &Q[static_cast<size_t>(k) * m];
        for (uint32_t j = 0; j < n; ++j) {
            const int32_t b_kj = b_row[j];
            if (b_kj == 0) continue; // deterministic skip of zero MACs
            const int8_t* v_row = &V[static_cast<size_t>(j) * m];
            for (uint32_t c = 0; c < m; ++c) {
                q_row[c] += b_kj * static_cast<int32_t>(v_row[c]);
            }
        }
    }
    return Q;
}

bool CheckCombineLimbBound(uint32_t n)
{
    // 4 balanced base-128 digits, each in [-64, 63], represent the ASYMMETRIC
    // range [-135,274,560, +133,160,895] — NOT [-2^27, 2^27): the positive
    // extreme is 63*(128^4-1)/(128-1) = 133,160,895 < 2^27, because the top
    // digit maxes at 63, not 64. DecomposeLimbPlanes discards any remainder past
    // 4 digits (no hot-loop assert), so an entry above the positive extreme
    // would decompose WRONG. P/Q entries span the symmetric range
    // |.| <= 15,625*n, so the binding constraint is the positive extreme and the
    // decomposition is total iff 15,625*n <= 133,160,895, i.e. n <= 8522 — still
    // covering the whole 4096..8192 dimension window (max entry 128,000,000).
    static_assert(kCombineLimbs == 4 && kCombineLimbBase == 128,
                  "limb bound derivation assumes 4 balanced base-128 digits");
    // Max positive 4-digit balanced base-128 value = 63 * (128^4 - 1) / 127.
    constexpr int64_t kLimbMaxPositive = 133'160'895;
    return static_cast<int64_t>(n) * int8_field::kElementSqBound <= kLimbMaxPositive;
}

std::vector<Fq> ComputeCombineModQClassical(const std::vector<int32_t>& P,
                                            const std::vector<int32_t>& Q,
                                            uint32_t n, uint32_t m)
{
    // Per-MAC FqFromInt32/FqMul/FqAdd path (pre-deferred reference). Kept as a
    // public oracle so ComputeCombineModQ's deferred __int128 reduction can be
    // proven byte-identical under adversarial max-magnitude inputs.
    std::vector<Fq> Chat(static_cast<size_t>(m) * m, 0);
    for (uint32_t a = 0; a < m; ++a) {
        const int32_t* p_row = &P[static_cast<size_t>(a) * n];
        Fq* chat_row = &Chat[static_cast<size_t>(a) * m];
        for (uint32_t k = 0; k < n; ++k) {
            const int32_t p_ak = p_row[k];
            if (p_ak == 0) continue;
            const Fq p_fq = int8_field::FqFromInt32(p_ak);
            const int32_t* q_row = &Q[static_cast<size_t>(k) * m];
            for (uint32_t c = 0; c < m; ++c) {
                chat_row[c] = int8_field::FqAdd(
                    chat_row[c], int8_field::FqMul(p_fq, int8_field::FqFromInt32(q_row[c])));
            }
        }
    }
    return Chat;
}

std::vector<Fq> ComputeCombineModQ(const std::vector<int32_t>& P,
                                   const std::vector<int32_t>& Q,
                                   uint32_t n, uint32_t m)
{
    // Deferred signed accumulation then one canonical reduction per output.
    // Equivalent to per-MAC FqFromInt32/FqMul/FqAdd because production
    // dimensions keep |sum_k P[a,k]*Q[k,c]| well below q = 2^61-1 (and inside
    // signed __int128). Avoids unnecessary per-MAC modular reductions.
    // BYTE-IDENTICAL to ComputeCombineModQClassical (pinned by unit tests).
    std::vector<Fq> Chat(static_cast<size_t>(m) * m, 0);
    std::vector<__int128> acc(m, 0);
    for (uint32_t a = 0; a < m; ++a) {
        const int32_t* p_row = &P[static_cast<size_t>(a) * n];
        std::fill(acc.begin(), acc.end(), 0);
        for (uint32_t k = 0; k < n; ++k) {
            const int32_t p_ak = p_row[k];
            if (p_ak == 0) continue;
            const int32_t* q_row = &Q[static_cast<size_t>(k) * m];
            for (uint32_t c = 0; c < m; ++c) {
                acc[c] += static_cast<__int128>(p_ak) * static_cast<__int128>(q_row[c]);
            }
        }
        Fq* chat_row = &Chat[static_cast<size_t>(a) * m];
        for (uint32_t c = 0; c < m; ++c) {
            if (acc[c] >= 0) {
                chat_row[c] = int8_field::FqReduce(static_cast<unsigned __int128>(acc[c]));
            } else {
                chat_row[c] = int8_field::FqNeg(
                    int8_field::FqReduce(static_cast<unsigned __int128>(-acc[c])));
            }
        }
    }
    return Chat;
}

namespace {

// Entrywise balanced base-2^7 digit decomposition (Appendix C-13):
//   x = sum_i digits[i] * 128^i,  digits[i] in [-64, 63],
// unique and deterministic for every |x| < 128^4/2 = 2^27 (checked by
// CheckCombineLimbBound). Each digit plane is a valid s8 tensor operand.
void DecomposeLimbPlanes(const std::vector<int32_t>& M, std::vector<int8_t>* planes)
{
    for (uint32_t l = 0; l < kCombineLimbs; ++l) {
        planes[l].resize(M.size());
    }
    for (size_t idx = 0; idx < M.size(); ++idx) {
        int32_t x = M[idx];
        for (uint32_t l = 0; l < kCombineLimbs; ++l) {
            // Balanced digit in [-64, 63]: d = ((x + 64) mod 128) - 64.
            const int32_t d = ((x + 64) & (kCombineLimbBase - 1)) - 64;
            planes[l][idx] = static_cast<int8_t>(d);
            x = (x - d) / kCombineLimbBase; // exact: (x - d) is a multiple of 128
        }
        // The decomposition is total under CheckCombineLimbBound; the remainder
        // MUST be fully consumed (x == 0), otherwise the top limb would silently
        // drop a nonzero high part and the combine would diverge from
        // ComputeCombineModQ. A valid (n, b) already gates |P|,|Q| <= 15,625*n
        // within the 4-digit range via CheckCombineLimbBound (now also enforced
        // up front by ValidateDims), so this can never fire on consensus-valid
        // input, and it is never reached on the verifier path (SketchFreivalds
        // does not decompose). RELEASE-LIVE HARD GUARD, not a debug-only no-op:
        // this project strips -DNDEBUG from every build configuration
        // (cmake/module/ProcessConfigurations.cmake), so the assert is compiled
        // into release builds and aborts (fail-CLOSED) on any violation instead
        // of committing a corrupt decomposition. Left as an assert deliberately
        // (F-L4): DecomposeLimbPlanes returns void on the hot combine path, so
        // abort-on-violation is the lower-risk fail-closed choice (no status to
        // thread through the tensor GEMM loop).
        assert(x == 0 && "DecomposeLimbPlanes: remainder not fully consumed "
                         "(entry exceeds the 4-digit base-2^7 range; "
                         "CheckCombineLimbBound must gate n)");
    }
}

} // namespace

std::vector<Fq> ComputeCombineLimbTensorStacked(const std::vector<int32_t>& P,
                                                const std::vector<int32_t>& Qstack,
                                                uint32_t n, uint32_t m,
                                                uint32_t q_cols)
{
    // Tensor-shaped combine (Appendix C-13), stacked across a nonce window
    // (§K.2b): 16 limb-pair m*q_cols*n products with exact s8xs8->s32
    // accumulation, then a single O(m*q_cols) shifted mod-q recombine. With
    // q_cols = Q*m this is the batched miner's ONE LARGE DENSE GEMM
    // P * [B_1*V | ... | B_Q*V]; with q_cols = m it is the single-nonce
    // consensus combine. Every limb-pair accumulator is exact: |sum_k d_i*d_j|
    // <= n*64*64 = n*2^12 < 2^31 for every header n <= 65,535 (§B.4 analogue).
    //
    // BYTE-EXACT equivalence to ComputeCombineModQ, per column block: as exact
    // integers,
    //   sum_k P[a][k]*Qstack[k][c] = sum_ij 128^(i+j) * S_ij[a][c],
    // so reducing each S_ij termwise with the canonical 128^(i+j) mod q weight
    // yields the same canonical residue; and each output entry depends only on
    // its own P row and Qstack column, so stacking columns changes no byte.
    // This function is the CPU consensus reference for the GPU backends'
    // tensor-core combine; on device the 16 limb-pair GEMMs are native
    // s8xs8->s32 IMMA/MFMA/TensorOps calls (the dominant, dense m x Q*m x n
    // shapes of the v4.1 batched profile, §K.2b).
    std::vector<int8_t> p_planes[kCombineLimbs];
    std::vector<int8_t> q_planes[kCombineLimbs];
    DecomposeLimbPlanes(P, p_planes);
    DecomposeLimbPlanes(Qstack, q_planes);

    // Precompute the canonical weights w_ij = 128^(i+j) mod q. All exponents
    // 7*(i+j) <= 42 < 61, so the weight is just the small power of two itself.
    Fq weight[kCombineLimbs][kCombineLimbs];
    for (uint32_t i = 0; i < kCombineLimbs; ++i) {
        for (uint32_t j = 0; j < kCombineLimbs; ++j) {
            weight[i][j] = static_cast<Fq>(1) << (7 * (i + j));
        }
    }

    const size_t out_size = static_cast<size_t>(m) * q_cols;
    std::vector<Fq> Chat(out_size, 0);
    std::vector<int32_t> S(out_size); // one limb-pair product at a time
    for (uint32_t i = 0; i < kCombineLimbs; ++i) {
        const std::vector<int8_t>& Pi = p_planes[i]; // m x n s8
        for (uint32_t j = 0; j < kCombineLimbs; ++j) {
            const std::vector<int8_t>& Qj = q_planes[j]; // n x q_cols s8
            // S = Pi * Qj, exact s8xs8->s32 (the tensor GEMM on device).
            std::fill(S.begin(), S.end(), 0);
            for (uint32_t a = 0; a < m; ++a) {
                const int8_t* p_row = &Pi[static_cast<size_t>(a) * n];
                int32_t* s_row = &S[static_cast<size_t>(a) * q_cols];
                for (uint32_t k = 0; k < n; ++k) {
                    const int32_t p_ak = p_row[k];
                    if (p_ak == 0) continue; // deterministic skip of zero MACs
                    const int8_t* q_row = &Qj[static_cast<size_t>(k) * q_cols];
                    for (uint32_t c = 0; c < q_cols; ++c) {
                        s_row[c] += p_ak * static_cast<int32_t>(q_row[c]);
                    }
                }
            }
            // O(m*q_cols) shifted mod-q recombine (integer ALU on device).
            const Fq w = weight[i][j];
            for (size_t idx = 0; idx < out_size; ++idx) {
                Chat[idx] = int8_field::FqAdd(
                    Chat[idx], int8_field::FqMul(w, int8_field::FqFromSigned(S[idx])));
            }
        }
    }
    return Chat;
}

std::vector<Fq> ComputeCombineLimbTensor(const std::vector<int32_t>& P,
                                         const std::vector<int32_t>& Q,
                                         uint32_t n, uint32_t m)
{
    // Single-nonce consensus combine: the q_cols = m instance of the stacked
    // path above (Appendix C-13). Kept as its own entry point because it is
    // the byte-exact CPU reference the unit tests pin against ComputeCombineModQ.
    return ComputeCombineLimbTensorStacked(P, Q, n, m, m);
}

std::vector<Fq> ComputeSketchOptimal(const std::vector<int8_t>& U,
                                     const std::vector<int8_t>& A,
                                     const std::vector<int8_t>& B,
                                     const std::vector<int8_t>& V,
                                     uint32_t n, uint32_t m)
{
    // Optimal miner factoring Chat = (U*A)(B*V) (§E.3), computed WITHOUT ever
    // forming the n x n product C. By integer-matrix associativity
    //     (U*A)(B*V) == U*(A*B)*V == U*C*V
    // as EXACT integer matrices, so this returns the byte-identical Chat to
    // ComputeSketch(U, ComputeExactProduct(A,B), V): identical integers reduce
    // to the identical UNIQUE canonical F_q residue in [0, q).
    //
    // Cost is ~2*n^2*m MACs (two rectangular GEMMs) plus the combine; the
    // direct mod-q combine is used here (CPU reference); GPU backends use the
    // byte-identical limb-tensor combine (ComputeCombineLimbTensor, C-13).
    const std::vector<int32_t> P = ComputeProjectedLeft(U, A, n, m);
    const std::vector<int32_t> Q = ComputeProjectedRight(B, V, n, m);
    return ComputeCombineModQ(P, Q, n, m);
}

std::vector<unsigned char> SerializeSketch(const std::vector<Fq>& sketch)
{
    std::vector<unsigned char> payload(sketch.size() * sizeof(uint64_t));
    for (size_t i = 0; i < sketch.size(); ++i) {
        WriteLE64(&payload[i * sizeof(uint64_t)], sketch[i]);
    }
    return payload;
}

bool ParseSketch(const std::vector<unsigned char>& payload, uint32_t m, std::vector<Fq>& sketch_out)
{
    const size_t expected_words = static_cast<size_t>(m) * m;
    if (payload.size() != expected_words * sizeof(uint64_t)) {
        return false;
    }
    sketch_out.resize(expected_words);
    for (size_t i = 0; i < expected_words; ++i) {
        const uint64_t word = ReadLE64(&payload[i * sizeof(uint64_t)]);
        // Canonicality check: reject any word >= q, mirroring v3's payload
        // range check (§D.3-(1)). Non-canonical residues could otherwise alias.
        if (word >= kFieldPrime) {
            return false;
        }
        sketch_out[i] = word;
    }
    return true;
}

uint256 ComputeSketchDigest(const uint256& sigma, const std::vector<unsigned char>& payload)
{
    // matmul_digest = H(sigma || Chat), domain-separated SHA256d (§E.1/§0.7-(3)).
    std::vector<unsigned char> buf;
    buf.reserve((sizeof(kSketchDigestTag) - 1) + uint256::size() + payload.size());
    buf.insert(buf.end(), kSketchDigestTag, kSketchDigestTag + (sizeof(kSketchDigestTag) - 1));
    buf.insert(buf.end(), sigma.data(), sigma.data() + uint256::size());
    buf.insert(buf.end(), payload.begin(), payload.end());
    return Sha256d(buf.data(), buf.size());
}

uint256 ComputeSketchDigestFromFq(const uint256& sigma, const std::vector<Fq>& sketch)
{
    // Streaming equivalent of ComputeSketchDigest(sigma, SerializeSketch(sketch)):
    // SHA256d(tag || sigma || LE64(sketch[0]) || ... || LE64(sketch[m^2-1])).
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(kSketchDigestTag), sizeof(kSketchDigestTag) - 1);
    outer.Write(sigma.data(), uint256::size());
    uint8_t word_le[8];
    for (Fq w : sketch) {
        WriteLE64(word_le, w);
        outer.Write(word_le, sizeof(word_le));
    }
    uint8_t mid[CSHA256::OUTPUT_SIZE];
    outer.Finalize(mid);
    CSHA256 inner;
    inner.Write(mid, sizeof(mid));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    inner.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

namespace {

// Derive the per-round Freivalds challenge seed (Fiat-Shamir): bind sigma and
// H(payload) so the miner cannot choose the payload after seeing the challenge
// (§D.1 step 1, invariant I7).
uint256 DeriveChallengeSeed(const uint256& sigma, const uint256& payload_hash, uint32_t round)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kFiatShamirTag), sizeof(kFiatShamirTag) - 1);
    hasher.Write(sigma.data(), uint256::size());
    hasher.Write(payload_hash.data(), uint256::size());
    uint8_t round_le[4];
    WriteLE32(round_le, round);
    hasher.Write(round_le, sizeof(round_le));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

} // namespace

bool SketchFreivalds(const std::vector<int8_t>& A,
                     const std::vector<int8_t>& B,
                     const std::vector<int8_t>& U,
                     const std::vector<int8_t>& V,
                     const std::vector<Fq>& sketch,
                     const uint256& sigma,
                     const std::vector<unsigned char>& payload,
                     uint32_t n, uint32_t m, uint32_t rounds)
{
    // Fail-closed on rounds == 0 (F-L3 defense-in-depth): an empty round set is
    // NOT a valid verification (a vacuous AND-of-rounds), so reject rather than
    // trivially accept. Every consensus caller (pow_v4::VerifySketch,
    // VerifySketchBMX4C, VerifySketchBMX4D) already pre-rejects rounds == 0
    // before reaching here, so this changes NO valid path; it only closes the
    // latent fail-OPEN if a future caller ever reaches this with rounds == 0.
    if (rounds == 0) {
        return false;
    }

    // H(Chat) = SHA256 of the serialized payload, bound into every challenge.
    uint8_t payload_hash_bytes[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(payload.data(), payload.size()).Finalize(payload_hash_bytes);
    const uint256 payload_hash{Span<const unsigned char>{payload_hash_bytes, sizeof(payload_hash_bytes)}};

    const std::vector<Fq> Uq = LiftS8ToFq(U); // m x n
    const std::vector<Fq> Vq = LiftS8ToFq(V); // n x m

    for (uint32_t round = 0; round < rounds; ++round) {
        const uint256 seed = DeriveChallengeSeed(sigma, payload_hash, round);

        // Challenge vectors x, y in F_q^m (§E.2), drawn from one wide
        // counter-mode F_q keystream: elements [0, m) are x, [m, 2m) are y.
        std::vector<Fq> xy(2 * static_cast<size_t>(m));
        int8_field::ExpandFqStream(seed, xy.size(), xy.data());
        const std::vector<Fq> x(xy.begin(), xy.begin() + m);
        const std::vector<Fq> y(xy.begin() + m, xy.end());

        // Left side: x^T Chat y in O(m^2).
        Fq lhs = 0;
        for (uint32_t a = 0; a < m; ++a) {
            const Fq* chat_row = &sketch[static_cast<size_t>(a) * m];
            Fq row_acc = 0;
            for (uint32_t c = 0; c < m; ++c) {
                row_acc = int8_field::FqAdd(row_acc, int8_field::FqMul(chat_row[c], y[c]));
            }
            lhs = int8_field::FqAdd(lhs, int8_field::FqMul(x[a], row_acc));
        }

        // Right side: (U^T x)^T A (B (V y)), never forming C.
        // vy = V * y   (n-vector), O(nm).
        std::vector<Fq> vy(n, 0);
        for (uint32_t j = 0; j < n; ++j) {
            const Fq* v_row = &Vq[static_cast<size_t>(j) * m];
            Fq acc = 0;
            for (uint32_t c = 0; c < m; ++c) {
                acc = int8_field::FqAdd(acc, int8_field::FqMul(v_row[c], y[c]));
            }
            vy[j] = acc;
        }
        // Bvy = B * vy  (n-vector), O(n^2).
        std::vector<Fq> Bvy(n, 0);
        for (uint32_t i = 0; i < n; ++i) {
            const int8_t* b_row = &B[static_cast<size_t>(i) * n];
            Fq acc = 0;
            for (uint32_t k = 0; k < n; ++k) {
                acc = int8_field::FqAdd(acc, int8_field::FqMul(int8_field::FqFromSigned(b_row[k]), vy[k]));
            }
            Bvy[i] = acc;
        }
        // ABvy = A * Bvy  (n-vector), O(n^2). This is the true C*(V y) reproduced
        // via two matvecs without ever materializing C (§D.1 step 2).
        std::vector<Fq> ABvy(n, 0);
        for (uint32_t i = 0; i < n; ++i) {
            const int8_t* a_row = &A[static_cast<size_t>(i) * n];
            Fq acc = 0;
            for (uint32_t k = 0; k < n; ++k) {
                acc = int8_field::FqAdd(acc, int8_field::FqMul(int8_field::FqFromSigned(a_row[k]), Bvy[k]));
            }
            ABvy[i] = acc;
        }
        // utx = U^T x   (n-vector), O(nm).
        std::vector<Fq> utx(n, 0);
        for (uint32_t a = 0; a < m; ++a) {
            const Fq xa = x[a];
            if (xa == 0) continue;
            const Fq* u_row = &Uq[static_cast<size_t>(a) * n];
            for (uint32_t i = 0; i < n; ++i) {
                utx[i] = int8_field::FqAdd(utx[i], int8_field::FqMul(u_row[i], xa));
            }
        }
        // rhs = utx . ABvy, O(n).
        Fq rhs = 0;
        for (uint32_t i = 0; i < n; ++i) {
            rhs = int8_field::FqAdd(rhs, int8_field::FqMul(utx[i], ABvy[i]));
        }

        if (lhs != rhs) {
            return false;
        }
    }
    return true;
}

} // namespace matmul::v4
