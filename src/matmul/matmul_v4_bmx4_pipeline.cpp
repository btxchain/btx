// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_bmx4_pipeline.h>

#include <arith_uint256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace matmul::v4::bmx4 {

bool CheckedMulSize(size_t a, size_t b, size_t& out)
{
    if (a != 0 && b > (static_cast<size_t>(-1) / a)) return false;
    out = a * b;
    return true;
}

bool CheckedAddSize(size_t a, size_t b, size_t& out)
{
    if (b > (static_cast<size_t>(-1) - a)) return false;
    out = a + b;
    return true;
}

namespace {

void DecomposeFourLimbs(const std::vector<int32_t>& M, std::vector<int8_t> (&limbs)[4])
{
    for (auto& p : limbs) p.resize(M.size());
    constexpr int32_t kHalf = 32;
    constexpr int32_t kBase = 64;
    for (size_t idx = 0; idx < M.size(); ++idx) {
        int32_t x = M[idx];
        for (uint32_t l = 0; l < 3; ++l) {
            const int32_t d = ((x + kHalf) & (kBase - 1)) - kHalf;
            limbs[l][idx] = static_cast<int8_t>(d);
            x = (x - d) / kBase;
        }
        limbs[3][idx] = static_cast<int8_t>(x);
    }
}

void BuildKaraPlanes(const std::vector<int8_t> (&limbs)[4], std::vector<int8_t> (&planes)[9])
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

} // namespace

PersistentSketchMinerBMX4C::PersistentSketchMinerBMX4C(const CBlockHeader& header, uint32_t n)
    : m_template{header}, m_n{n}
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) return;
    m_m = m;
    m_template_hash = matmul::v4::ComputeTemplateHash(m_template);
    m_plan = PlanExactAccelLanes("cpu"); // host reference lane; device backends override
    m_plan.combine = CombineLane::Karatsuba9Int8;

    const uint256 seed_a = DeriveOperandSeedBMX4C(m_template, matmul::v4::Operand::A);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4C(m_template);

    // Portable XOF for template-scoped operands (same bytes as ExpandOperand*).
    const size_t nn = static_cast<size_t>(n) * n;
    std::vector<int8_t> mu_a(nn);
    ExpandMantissaStreamPortable(seed_a, nn, mu_a.data());
    std::vector<uint8_t> scale_a(static_cast<size_t>(n) * (n / kBlockLen));
    ExpandScaleStreamPortable(seed_a, scale_a.size(), scale_a.data());
    m_A.resize(nn);
    for (uint32_t i = 0; i < n; ++i) {
        const size_t row = static_cast<size_t>(i) * n;
        const size_t srow = static_cast<size_t>(i) * (n / kBlockLen);
        for (uint32_t k = 0; k < n; ++k) {
            m_A[row + k] = static_cast<int8_t>(
                static_cast<int32_t>(mu_a[row + k]) * (1 << scale_a[srow + (k / kBlockLen)]));
        }
    }
    m_U = ExpandProjectorBMX4C(seed_u, m_m, n);
    m_V = ExpandProjectorBMX4C(seed_v, n, m_m);
    m_P = matmul::v4::ComputeProjectedLeft(m_U, m_A, n, m_m);

    std::vector<int8_t> p_limbs[4];
    DecomposeFourLimbs(m_P, p_limbs);
    BuildKaraPlanes(p_limbs, m_P_kara);

    m_ring.resize(3);
    m_adaptive_q = m_requested_q;
    m_valid = true;
}

void PersistentSketchMinerBMX4C::SetRequestedQ(uint32_t q)
{
    m_requested_q = q == 0 ? 1 : q;
    if (m_adaptive_q > m_requested_q) m_adaptive_q = m_requested_q;
}

bool PersistentSketchMinerBMX4C::EnsureQCapacity(uint32_t q, std::string& error)
{
    // Checked sizing for one nonce slot's Q / Chat working set.
    size_t nm = 0;
    size_t mm = 0;
    size_t nn = 0;
    if (!CheckedMulSize(m_n, m_m, nm) || !CheckedMulSize(m_m, m_m, mm) ||
        !CheckedMulSize(m_n, m_n, nn)) {
        error = "PersistentSketchMinerBMX4C: dimension overflow";
        return false;
    }
    (void)q;
    for (auto& slot : m_ring) {
        slot.Bhat.resize(nn);
        slot.Q.resize(nm);
        slot.Chat.resize(mm);
    }
    m_adaptive_q = std::min(m_adaptive_q, std::max(q, uint32_t{1}));
    return true;
}

void PersistentSketchMinerBMX4C::StageXof(NonceSlot& slot)
{
    slot.sigma = matmul::v4::DeriveSigma(slot.header);
    slot.seed_b = DeriveOperandSeedBMX4C(slot.header, matmul::v4::Operand::B);
    // Portable XOF + dequant (device-resident packing schedule on the host).
    const size_t nn = static_cast<size_t>(m_n) * m_n;
    std::vector<int8_t> mu(nn);
    ExpandMantissaStreamPortable(slot.seed_b, nn, mu.data());
    std::vector<uint8_t> scale(static_cast<size_t>(m_n / kBlockLen) * m_n);
    ExpandScaleStreamPortable(slot.seed_b, scale.size(), scale.data());
    for (uint32_t k = 0; k < m_n; ++k) {
        const size_t row = static_cast<size_t>(k) * m_n;
        const size_t srow = static_cast<size_t>(k / kBlockLen) * m_n;
        for (uint32_t j = 0; j < m_n; ++j) {
            slot.Bhat[row + j] = static_cast<int8_t>(
                static_cast<int32_t>(mu[row + j]) * (1 << scale[srow + j]));
        }
    }
    slot.ready_xof = true;
    slot.ready_combine = false;
    slot.ready_hash = false;
    ++m_stats.xof_stage_calls;
}

void PersistentSketchMinerBMX4C::StageCombine(NonceSlot& slot)
{
    assert(slot.ready_xof);
    slot.Q = matmul::v4::ComputeProjectedRight(slot.Bhat, m_V, m_n, m_m);
    // Karatsuba-9 combine against template-cached P (byte-identical path).
    slot.Chat = ComputeCombineKaratsuba9BMX4C(m_P, slot.Q, m_n, m_m);
    slot.ready_combine = true;
    ++m_stats.combine_stage_calls;
}

void PersistentSketchMinerBMX4C::StageHash(NonceSlot& slot, const uint256& target,
                                          DigestOnlyResultBMX4C& result,
                                          std::vector<unsigned char>* payload_out,
                                          bool retain_winner_payload)
{
    assert(slot.ready_combine);
    // Stream LE F_q words into SHA256d — no 8 MiB loser payload allocation.
    slot.digest = matmul::v4::ComputeSketchDigestFromFq(slot.sigma, slot.Chat);
    slot.ready_hash = true;
    ++m_stats.hash_stage_calls;

    result.nonce = slot.header.nNonce64;
    result.digest = slot.digest;
    result.target_match = UintToArith256(slot.digest) <= UintToArith256(target);
    result.backend_status = DigestOnlyBackendStatus::Ok;
    if (result.target_match) ++m_stats.winners;

    if (payload_out != nullptr) {
        if (retain_winner_payload && result.target_match) {
            *payload_out = matmul::v4::SerializeSketch(slot.Chat);
        } else {
            payload_out->clear();
        }
    }
    // Drop Chat after hashing unless a winner payload was requested (already serialized).
    if (!(retain_winner_payload && result.target_match && payload_out != nullptr)) {
        // Keep Chat buffer capacity for reuse; clear logical contents.
        std::fill(slot.Chat.begin(), slot.Chat.end(), Fq{0});
    }
}

bool PersistentSketchMinerBMX4C::MineDigestsOnly(const std::vector<CBlockHeader>& headers,
                                                 const uint256& target,
                                                 std::vector<DigestOnlyResultBMX4C>& out,
                                                 std::vector<std::vector<unsigned char>>* payloads_out,
                                                 bool retain_winner_payload)
{
    out.clear();
    if (payloads_out != nullptr) payloads_out->clear();
    m_stats = PipelineStats{};
    if (!m_valid || headers.empty()) return false;

    for (const auto& h : headers) {
        if (matmul::v4::ComputeTemplateHash(h) != m_template_hash) return false;
    }

    std::string error;
    const uint32_t count = static_cast<uint32_t>(headers.size());
    uint32_t q = std::min(m_requested_q, count);
    // Adaptive shrink on pathological sizes (checked arithmetic failure).
    while (q >= 1) {
        if (EnsureQCapacity(q, error)) break;
        if (q == 1) return false;
        q /= 2;
    }
    m_adaptive_q = q;
    m_stats.adaptive_q = m_adaptive_q;
    m_stats.windows = (count + m_adaptive_q - 1) / m_adaptive_q;

    out.resize(count);
    if (payloads_out != nullptr) payloads_out->resize(count);

    // Triple-buffer pipeline:
    //   buffer N+1: XOF/pack, buffer N: combine, buffer N-1: hash/target.
    // Three ring slots hold live state; stages are ordered so a device backend
    // can map them onto three streams without changing results.
    auto& slot0 = m_ring[0];
    slot0.header = headers[0];
    StageXof(slot0);

    for (uint32_t i = 0; i < count; ++i) {
        if (i + 1 < count) {
            NonceSlot& next = m_ring[(i + 1) % 3];
            next.header = headers[i + 1];
            StageXof(next); // buffer N+1
        }
        NonceSlot& cur = m_ring[i % 3];
        StageCombine(cur); // buffer N
        if (i >= 1) {
            NonceSlot& prev = m_ring[(i - 1) % 3];
            StageHash(prev, target, out[i - 1],
                      payloads_out != nullptr ? &(*payloads_out)[i - 1] : nullptr,
                      retain_winner_payload); // buffer N-1
        }
    }
    NonceSlot& last = m_ring[(count - 1) % 3];
    StageHash(last, target, out[count - 1],
              payloads_out != nullptr ? &(*payloads_out)[count - 1] : nullptr,
              retain_winner_payload);
    return true;
}

} // namespace matmul::v4::bmx4
