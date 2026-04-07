// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_V2_CHAIN_GROWTH_PROJECTION_REPORT_H
#define BTX_TEST_SHIELDED_V2_CHAIN_GROWTH_PROJECTION_REPORT_H

#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace btx::test::shieldedv2growth {

enum class RepresentativeFamily : uint8_t {
    DIRECT_SEND = 1,
    INGRESS_BATCH = 2,
    EGRESS_BATCH = 3,
    REBALANCE = 4,
    SETTLEMENT_ANCHOR = 5,
};

struct FamilyFootprint
{
    RepresentativeFamily family{RepresentativeFamily::DIRECT_SEND};
    uint64_t serialized_size_bytes{0};
    uint64_t tx_weight{0};
    uint64_t verify_units{0};
    uint64_t scan_units{0};
    uint64_t tree_update_units{0};
    uint64_t logical_actions_per_tx{1};
    uint64_t commitments_per_tx{0};
    uint64_t nullifiers_per_tx{0};
};

struct BlockLimitConfig
{
    std::string label;
    uint64_t block_serialized_limit_bytes{0};
    uint64_t block_weight_limit{0};
    uint64_t block_verify_limit{0};
    uint64_t block_scan_limit{0};
    uint64_t block_tree_update_limit{0};
};

struct WorkloadScenarioConfig
{
    std::string label;
    uint64_t boundary_actions_per_day{0};
    uint32_t direct_send_share_bps{0};
    uint32_t ingress_batch_share_bps{0};
    uint32_t egress_batch_share_bps{0};
    uint32_t settlement_windows_per_day{0};
};

struct StateRetentionConfig
{
    uint64_t commitment_index_key_bytes{9};
    uint64_t commitment_index_value_bytes{32};
    uint64_t snapshot_commitment_bytes{32};
    uint64_t nullifier_index_key_bytes{33};
    uint64_t nullifier_index_value_bytes{1};
    uint64_t snapshot_nullifier_bytes{32};
    uint64_t nullifier_cache_bytes{96};
    uint64_t bounded_anchor_history_bytes_per_settlement_window{800};
    uint64_t snapshot_target_bytes{2'642'412'320ULL};
    bool retain_commitment_index{false};
    bool retain_nullifier_index{true};
    bool snapshot_include_commitments{false};
    bool snapshot_include_nullifiers{true};
};

struct RuntimeReportConfig
{
    uint64_t block_interval_seconds{90};
    std::vector<FamilyFootprint> families;
    std::vector<BlockLimitConfig> block_limits;
    std::vector<WorkloadScenarioConfig> workloads;
    StateRetentionConfig state_retention;
};

UniValue BuildRuntimeReport(const RuntimeReportConfig& config);

} // namespace btx::test::shieldedv2growth

#endif // BTX_TEST_SHIELDED_V2_CHAIN_GROWTH_PROJECTION_REPORT_H
