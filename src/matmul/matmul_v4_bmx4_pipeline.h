// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_BMX4_PIPELINE_H
#define BTX_MATMUL_MATMUL_V4_BMX4_PIPELINE_H

#include <matmul/matmul_v4_bmx4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// Persistent, triple-buffered ENC-BMX4C mining pipeline (exact-accel step 1+3).
//
// Host-side reference of the device-resident nonce loop:
//   buffer N+1: exact SHA-256 XOF + stable rejection compaction + packing
//   buffer N:   projection + Karatsuba-9 combine
//   buffer N-1: canonical serialization hash + target scan
//
// Cross-call reuse: template-scoped A/U/V/P and Karatsuba planes of P are paid
// once per template; Q working sets resize adaptively and are reused across
// MineDigestsOnly windows. Consensus bytes are unchanged (byte-identical to
// ComputeDigestBMX4C). Miner-local only; mainnet activation stays inert.

namespace matmul::v4::bmx4 {

/** Checked size helpers used by adaptive Q allocation. */
[[nodiscard]] bool CheckedMulSize(size_t a, size_t b, size_t& out);
[[nodiscard]] bool CheckedAddSize(size_t a, size_t b, size_t& out);

/**
 * Persistent template-scoped miner. Construct once per block template; call
 * MineDigestsOnly repeatedly over nonce windows. Prefer this over constructing
 * a fresh BatchedSketchMinerBMX4C per window when the host (or a future device
 * backend) wants cross-call buffer reuse.
 */
class PersistentSketchMinerBMX4C
{
public:
    PersistentSketchMinerBMX4C(const CBlockHeader& header, uint32_t n);

    [[nodiscard]] bool Valid() const { return m_valid; }
    [[nodiscard]] uint32_t SketchDim() const { return m_m; }
    [[nodiscard]] uint32_t Dimension() const { return m_n; }
    [[nodiscard]] const uint256& TemplateHash() const { return m_template_hash; }
    [[nodiscard]] uint32_t AdaptiveQ() const { return m_adaptive_q; }
    [[nodiscard]] const ExactAccelPlan& Plan() const { return m_plan; }

    /** Requested window size; may shrink on allocation pressure (never below 1). */
    void SetRequestedQ(uint32_t q);

    /**
     * Triple-buffered digest-only mine over `headers` (all must project onto
     * this template). Stages overlap on the host via three ring slots:
     *   prepare(N+1) while combine(N) while hash(N-1).
     * Loser payloads are never allocated. Winner payloads are filled only when
     * `payloads_out != nullptr` and `retain_winner_payload`.
     */
    [[nodiscard]] bool MineDigestsOnly(const std::vector<CBlockHeader>& headers,
                                       const uint256& target,
                                       std::vector<DigestOnlyResultBMX4C>& out,
                                       std::vector<std::vector<unsigned char>>* payloads_out = nullptr,
                                       bool retain_winner_payload = true);

    /** Pipeline telemetry (reset each MineDigestsOnly call). */
    struct PipelineStats {
        uint32_t windows{0};
        uint32_t xof_stage_calls{0};
        uint32_t combine_stage_calls{0};
        uint32_t hash_stage_calls{0};
        uint32_t winners{0};
        uint32_t adaptive_q{0};
    };
    [[nodiscard]] const PipelineStats& LastStats() const { return m_stats; }

private:
    struct NonceSlot {
        CBlockHeader header;
        uint256 sigma;
        uint256 seed_b;
        std::vector<int8_t> Bhat;     // packed / dequantized B
        std::vector<int32_t> Q;       // n x m
        std::vector<Fq> Chat;         // m x m
        uint256 digest;
        bool ready_xof{false};
        bool ready_combine{false};
        bool ready_hash{false};
    };

    [[nodiscard]] bool EnsureQCapacity(uint32_t q, std::string& error);
    void StageXof(NonceSlot& slot);
    void StageCombine(NonceSlot& slot);
    void StageHash(NonceSlot& slot, const uint256& target, DigestOnlyResultBMX4C& result,
                   std::vector<unsigned char>* payload_out, bool retain_winner_payload);

    CBlockHeader m_template;
    uint256 m_template_hash;
    uint32_t m_n{0};
    uint32_t m_m{0};
    bool m_valid{false};
    ExactAccelPlan m_plan{};
    uint32_t m_requested_q{32};
    uint32_t m_adaptive_q{32};

    // Template-scoped caches (cross-call).
    std::vector<int8_t> m_A;
    std::vector<int8_t> m_U;
    std::vector<int8_t> m_V;
    std::vector<int32_t> m_P;
    std::vector<int8_t> m_P_kara[9]; // precomputed Karatsuba planes of P

    // Reusable per-window scratch (resized by EnsureQCapacity).
    std::vector<NonceSlot> m_ring; // 3 slots
    PipelineStats m_stats{};
};

} // namespace matmul::v4::bmx4

#endif // BTX_MATMUL_MATMUL_V4_BMX4_PIPELINE_H
