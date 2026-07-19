// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_BMX4_CONTEXT_H
#define BITCOIN_CUDA_MATMUL_V4_BMX4_CONTEXT_H

#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_bmx4_pipeline.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// Template-scoped persistent CUDA mining context (exact-accel redesign step 1).
//
// Cross-call reuse of host-exact pipeline state (A/U/V/P, Karatsuba planes,
// adaptive Q, triple-buffer ring). Device buffer handles are reserved for the
// CUDA bring-up; until then the host PersistentSketchMinerBMX4C is the
// normative device-resident schedule (XOF → Karatsuba-9 → streaming digest).
//
// Pipeline:
//   buffer N+1: exact SHA-256 XOF + stable rejection compaction + packing
//   buffer N:   projection + Karatsuba-9 combine
//   buffer N-1: canonical serialization hash + target scan
//
// Activation remains inert. One independent nonce range + context per GPU.

namespace matmul_v4::cuda {

struct Bmx4TemplateContextKey {
    uint256 template_hash;
    uint32_t n{0};
    int device_index{-1};
    matmul::v4::bmx4::ExactAccelPlan plan{};
};

class Bmx4CudaTemplateContext
{
public:
    [[nodiscard]] static Bmx4CudaTemplateContext& Instance();

    /** Bind or refresh the template-scoped persistent miner. */
    [[nodiscard]] bool EnsureTemplate(const CBlockHeader& header, uint32_t n,
                                      const matmul::v4::bmx4::ExactAccelPlan& plan,
                                      std::string& error);

    [[nodiscard]] bool EnsureTemplate(const Bmx4TemplateContextKey& key, std::string& error) = delete;

    [[nodiscard]] const Bmx4TemplateContextKey& Key() const { return m_key; }
    [[nodiscard]] bool Ready() const { return m_ready && m_miner && m_miner->Valid(); }

    [[nodiscard]] uint32_t AdaptiveQ() const
    {
        return m_miner ? m_miner->AdaptiveQ() : m_adaptive_q;
    }
    void SetRequestedQ(uint32_t q);

    /** Digest-only mine through the persistent triple-buffer pipeline. */
    [[nodiscard]] bool MineDigestsOnly(const std::vector<CBlockHeader>& headers,
                                       const uint256& target,
                                       std::vector<matmul::v4::bmx4::DigestOnlyResultBMX4C>& out,
                                       std::vector<std::vector<unsigned char>>* payloads_out = nullptr,
                                       bool retain_winner_payload = true);

    [[nodiscard]] static bool CheckedMul(size_t a, size_t b, size_t& out)
    {
        return matmul::v4::bmx4::CheckedMulSize(a, b, out);
    }

private:
    Bmx4CudaTemplateContext() = default;

    std::mutex m_mu;
    Bmx4TemplateContextKey m_key{};
    bool m_ready{false};
    uint32_t m_adaptive_q{32};
    std::unique_ptr<matmul::v4::bmx4::PersistentSketchMinerBMX4C> m_miner;
};

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_BMX4_CONTEXT_H
