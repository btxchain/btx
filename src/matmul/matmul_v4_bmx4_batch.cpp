// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_bmx4_batch.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

namespace matmul::v4::bmx4 {

BatchedSketchMinerBMX4C::BatchedSketchMinerBMX4C(const CBlockHeader& header, uint32_t n)
    : m_template{header}, m_n{n}
{
    uint32_t m = 0;
    // ValidateDimsBMX4C is the ENC-BMX4C ValidateDims: the v4 (n>0, b|n, s32
    // accum) checks PLUS n % 32 == 0 (E8M0 block scales) and
    // CheckCombineLimbBoundBMX4C(n) (288*n <= 2^23-1).
    if (!ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) return;
    m_m = m;
    m_template_hash = matmul::v4::ComputeTemplateHash(m_template);

    // Template-scoped derivations (invariant I1', §1.5): seed_A / seed_U /
    // seed_V bind the template hash only, so Ahat, U, V — and the left factor
    // P = U*Ahat — are paid ONCE per template. The per-nonce marginal work is
    // {expand Bhat, Bhat*V, stacked combine, digest}.
    const uint256 seed_a = DeriveOperandSeedBMX4C(m_template, matmul::v4::Operand::A);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4C(m_template);
    m_A = ExpandOperandA(seed_a, n);
    m_U = ExpandProjectorBMX4C(seed_u, m_m, n);
    m_V = ExpandProjectorBMX4C(seed_v, n, m_m);
    // P = U*Ahat: reuses the UNCHANGED exact s8xs8->s32 projection (|Ahat|<=48,
    // |U|<=6 both fit s8), byte-identical to ComputeDigestBMX4C's ComputeProjectedLeft.
    m_P = matmul::v4::ComputeProjectedLeft(m_U, m_A, n, m_m);
    m_valid = true;
}

bool BatchedSketchMinerBMX4C::Mine(const std::vector<CBlockHeader>& headers,
                                   std::vector<BatchNonceResultBMX4C>& out) const
{
    out.clear();
    if (!m_valid || headers.empty()) return false;
    const uint32_t count = static_cast<uint32_t>(headers.size());
    const uint32_t q_cols = count * m_m;

    // Per-nonce right factors Q_i = Bhat_i*V written into the horizontal stack
    // Qstack = [Bhat_1*V | ... | Bhat_Q*V] (n x count*m, row-major). Only Bhat
    // is nonce-fresh (invariant I1'); sigma is derived per header so the digest
    // binds the nonce.
    std::vector<uint256> sigmas(count);
    std::vector<int32_t> Qstack(static_cast<size_t>(m_n) * q_cols);
    for (uint32_t idx = 0; idx < count; ++idx) {
        const CBlockHeader& header = headers[idx];
        // Fail closed on a template mismatch: combining a stale template's
        // cached A/U/V/P with a fresh header would produce non-consensus digests.
        if (matmul::v4::ComputeTemplateHash(header) != m_template_hash) {
            out.clear();
            return false;
        }
        sigmas[idx] = matmul::v4::DeriveSigma(header);
        const uint256 seed_b = DeriveOperandSeedBMX4C(header, matmul::v4::Operand::B);
        const std::vector<int8_t> Bhat = ExpandOperandB(seed_b, m_n);
        const std::vector<int32_t> Qi = matmul::v4::ComputeProjectedRight(Bhat, m_V, m_n, m_m);
        for (uint32_t k = 0; k < m_n; ++k) {
            int32_t* dst = &Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(idx) * m_m];
            const int32_t* src = &Qi[static_cast<size_t>(k) * m_m];
            std::copy(src, src + m_m, dst);
        }
    }

    // ONE LARGE DENSE GEMM: Chat_wide = P * Qstack (m x n by n x count*m),
    // through the UNCHANGED limb-tensor path. Byte-identical per column block to
    // the single-nonce ComputeCombineModQ the ENC-BMX4C reference uses (both
    // equal P*Q mod q as exact integers, canonical residues unique).
    const std::vector<Fq> Chat_wide =
        matmul::v4::ComputeCombineLimbTensorStacked(m_P, Qstack, m_n, m_m, q_cols);

    out.reserve(count);
    for (uint32_t idx = 0; idx < count; ++idx) {
        std::vector<Fq> Chat(static_cast<size_t>(m_m) * m_m);
        for (uint32_t a = 0; a < m_m; ++a) {
            const Fq* src = &Chat_wide[static_cast<size_t>(a) * q_cols + static_cast<size_t>(idx) * m_m];
            std::copy(src, src + m_m, &Chat[static_cast<size_t>(a) * m_m]);
        }
        BatchNonceResultBMX4C res;
        res.nonce = headers[idx].nNonce64;
        res.payload = matmul::v4::SerializeSketch(Chat);
        res.digest = matmul::v4::ComputeSketchDigest(sigmas[idx], res.payload);
        out.push_back(std::move(res));
    }
    return true;
}

bool BatchedSketchMinerBMX4C::Mine(uint64_t start_nonce, uint32_t count,
                                   std::vector<BatchNonceResultBMX4C>& out) const
{
    out.clear();
    if (!m_valid || count == 0) return false;
    std::vector<CBlockHeader> headers(count, m_template);
    for (uint32_t idx = 0; idx < count; ++idx) {
        headers[idx].nNonce64 = start_nonce + idx;
        headers[idx].nNonce = static_cast<uint32_t>(headers[idx].nNonce64);
    }
    return Mine(headers, out);
}

} // namespace matmul::v4::bmx4
