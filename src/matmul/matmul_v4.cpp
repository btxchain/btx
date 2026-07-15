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
    m_out = n / b;
    return true;
}

uint256 DeriveSigma(const CBlockHeader& header)
{
    // sigma = SHA256d(full header) -- reuse the v3 rule so nNonce64 and every
    // other header field are bound (§A.2, invariant I7).
    return matmul::DeriveSigma(header);
}

uint256 DeriveOperandSeed(const CBlockHeader& header, Operand which)
{
    // Bind every header field via the canonical v3 header hash, then
    // domain-separate by operand byte 'A'/'B' (§A.2). Because the header hash
    // folds nNonce64 and hashPrevBlock, operands are nonce-fresh and cannot be
    // precomputed before the parent block exists (invariant I1).
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);

    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kSeedTag), sizeof(kSeedTag) - 1);
    hasher.Write(header_hash.data(), uint256::size());
    const uint8_t which_byte = static_cast<uint8_t>(which);
    hasher.Write(&which_byte, 1);

    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

std::pair<uint256, uint256> DeriveProjectorSeeds(const uint256& sigma)
{
    auto derive = [&sigma](const char* tag, size_t taglen) {
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
        hasher.Write(sigma.data(), uint256::size());
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
    // Cost is ~2*n^2*m MACs (two rectangular GEMMs + an m x m combine) versus
    // the Theta(n^3) full product; the projector stages are the same ones the
    // GPU backends fold in (§E.3).

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

    // Combine Chat[a][c] = (sum_k P[a][k]*Q[k][c]) mod q over F_q. P,Q entries are
    // exact int32 (|.| < 2^30); lift each to its canonical F_q image and MAC with
    // the same FqFromInt32/FqMul/FqAdd used by ComputeSketch, so the accumulated
    // residue is the canonical (U*C*V)[a][c] mod q -- identical to the full path.
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
                chat_row[c] = int8_field::FqAdd(chat_row[c],
                                                int8_field::FqMul(p_fq, int8_field::FqFromInt32(q_row[c])));
            }
        }
    }
    return Chat;
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
    if (rounds == 0) {
        return true;
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
