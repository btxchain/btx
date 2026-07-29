// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_batch.h>

#include <arith_uint256.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace matmul::v4 {

BatchedSketchMiner::BatchedSketchMiner(const CBlockHeader& header, uint32_t n)
    : m_template{header}, m_n{n}
{
    uint32_t m = 0;
    if (!ValidateDims(n, kTileB, m)) return;
    if (!CheckCombineLimbBound(n)) return;
    m_m = m;
    m_template_hash = ComputeTemplateHash(m_template);

    // Template-scoped derivations (§A.2 v4.1, invariant I1'): A, U, V bind the
    // template hash only, so they — and the left factor P = U*A — are paid
    // ONCE per template instead of per nonce. This is the §K.2b amortization:
    // the per-nonce marginal work drops to {expand B, B*V, stacked combine,
    // digest}, and difficulty MUST be calibrated against that marginal unit.
    const uint256 seed_a = DeriveOperandSeed(m_template, Operand::A);
    const auto [seed_u, seed_v] = DeriveProjectorSeeds(m_template);
    m_A = ExpandOperand(seed_a, n);
    m_U = ExpandProjector(seed_u, m_m, n);
    m_V = ExpandProjector(seed_v, n, m_m);
    m_P = ComputeProjectedLeft(m_U, m_A, n, m_m);
    m_valid = true;
}

bool BatchedSketchMiner::Mine(const std::vector<CBlockHeader>& headers,
                              std::vector<BatchNonceResult>& out) const
{
    return MineImpl(headers, /*target=*/nullptr, out);
}

bool BatchedSketchMiner::Mine(const std::vector<CBlockHeader>& headers,
                              const uint256& target,
                              std::vector<BatchNonceResult>& out) const
{
    return MineImpl(headers, &target, out);
}

bool BatchedSketchMiner::MineImpl(const std::vector<CBlockHeader>& headers,
                                  const uint256* target,
                                  std::vector<BatchNonceResult>& out) const
{
    out.clear();
    if (!m_valid || headers.empty()) return false;
    const uint32_t count = static_cast<uint32_t>(headers.size());
    const uint32_t q_cols = count * m_m;

    // Per-nonce right factors Q_i = B_i*V, written directly into the
    // horizontal stack Qstack = [B_1*V | ... | B_Q*V] (n x count*m,
    // row-major). Only B is nonce-fresh (invariant I1'); sigma is derived per
    // header so the digest binds the nonce. On device this loop is itself one
    // stacked GEMM [B_1; ...; B_Q] * V with the B expansions overlapped.
    std::vector<uint256> sigmas(count);
    std::vector<int32_t> Qstack(static_cast<size_t>(m_n) * q_cols);
    for (uint32_t idx = 0; idx < count; ++idx) {
        const CBlockHeader& header = headers[idx];
        // Fail closed on a template mismatch: combining a stale template's
        // cached A/U/V/P with a fresh header would produce digests that are
        // NOT the consensus digests for that header.
        if (ComputeTemplateHash(header) != m_template_hash) {
            out.clear();
            return false;
        }
        sigmas[idx] = DeriveSigma(header);
        const uint256 seed_b = DeriveOperandSeed(header, Operand::B);
        const std::vector<int8_t> B = ExpandOperand(seed_b, m_n);
        const std::vector<int32_t> Qi = ComputeProjectedRight(B, m_V, m_n, m_m);
        for (uint32_t k = 0; k < m_n; ++k) {
            int32_t* dst = &Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(idx) * m_m];
            const int32_t* src = &Qi[static_cast<size_t>(k) * m_m];
            std::copy(src, src + m_m, dst);
        }
    }

    // ONE LARGE DENSE GEMM (§K.2b): Chat_wide = P * Qstack (m x n by
    // n x count*m), evaluated through the limb-tensor path (Appendix C-13) —
    // byte-identical per column block to the single-nonce combine.
    const std::vector<Fq> Chat_wide = ComputeCombineLimbTensorStacked(m_P, Qstack, m_n, m_m, q_cols);

    // Slice per nonce, serialize, digest. H7 two-phase: the digest binds the
    // full serialized sketch (H(sigma||SerializeSketch(Chat))), so each
    // candidate's 8·m² payload is materialized into a REUSED scratch buffer to
    // compute the digest, but is retained in out[idx].payload only when it is a
    // winner/share (digest <= *target). Losing nonces leave payload empty, so at
    // most one loser payload lives at a time (plus retained winners) instead of
    // Q simultaneous 8 MiB payloads. With target==nullptr every payload is
    // retained (single-phase behaviour, byte-identical to the legacy Mine).
    const std::optional<arith_uint256> bnTarget =
        target != nullptr ? std::optional<arith_uint256>(UintToArith256(*target)) : std::nullopt;
    out.reserve(count);
    std::vector<unsigned char> scratch;
    for (uint32_t idx = 0; idx < count; ++idx) {
        std::vector<Fq> Chat(static_cast<size_t>(m_m) * m_m);
        for (uint32_t a = 0; a < m_m; ++a) {
            const Fq* src = &Chat_wide[static_cast<size_t>(a) * q_cols + static_cast<size_t>(idx) * m_m];
            std::copy(src, src + m_m, &Chat[static_cast<size_t>(a) * m_m]);
        }
        scratch = SerializeSketch(Chat);
        BatchNonceResult res;
        res.nonce = headers[idx].nNonce64;
        res.digest = ComputeSketchDigest(sigmas[idx], scratch);
        const bool retain_payload =
            !bnTarget.has_value() || UintToArith256(res.digest) <= *bnTarget;
        if (retain_payload) {
            res.payload = std::move(scratch);
        }
        out.push_back(std::move(res));
    }
    return true;
}

bool BatchedSketchMiner::Mine(uint64_t start_nonce, uint32_t count,
                              std::vector<BatchNonceResult>& out) const
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

} // namespace matmul::v4
