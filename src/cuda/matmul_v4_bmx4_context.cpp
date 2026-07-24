// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_bmx4_context.h>

#include <matmul/matmul_v4.h>

namespace matmul_v4::cuda {

Bmx4CudaTemplateContext& Bmx4CudaTemplateContext::Instance()
{
    static Bmx4CudaTemplateContext ctx;
    return ctx;
}

bool Bmx4CudaTemplateContext::EnsureTemplate(const CBlockHeader& header, uint32_t n,
                                             const matmul::v4::bmx4::ExactAccelPlan& plan,
                                             std::string& error)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const uint256 th = matmul::v4::ComputeTemplateHash(header);
    if (m_ready && m_miner && m_miner->Valid() && m_key.template_hash == th && m_key.n == n) {
        m_key.plan = plan;
        error.clear();
        return true; // cross-call hit
    }

    auto miner = std::make_unique<matmul::v4::bmx4::PersistentSketchMinerBMX4C>(header, n);
    if (!miner->Valid()) {
        error = "Bmx4CudaTemplateContext: invalid ENC-BMX4C dimensions";
        m_ready = false;
        m_miner.reset();
        return false;
    }
    miner->SetRequestedQ(m_adaptive_q);
    m_miner = std::move(miner);
    m_key.template_hash = th;
    m_key.n = n;
    m_key.plan = plan;
    m_ready = true;
    error.clear();
    return true;
}

void Bmx4CudaTemplateContext::SetRequestedQ(uint32_t q)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_adaptive_q = q == 0 ? 1 : q;
    if (m_miner) m_miner->SetRequestedQ(m_adaptive_q);
}

bool Bmx4CudaTemplateContext::MineDigestsOnly(const std::vector<CBlockHeader>& headers,
                                              const uint256& target,
                                              std::vector<matmul::v4::bmx4::DigestOnlyResultBMX4C>& out,
                                              std::vector<std::vector<unsigned char>>* payloads_out,
                                              bool retain_winner_payload)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!m_ready || !m_miner || !m_miner->Valid()) return false;
    return m_miner->MineDigestsOnly(headers, target, out, payloads_out, retain_winner_payload);
}

} // namespace matmul_v4::cuda
