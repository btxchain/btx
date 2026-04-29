// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_RELAY_FIXTURE_BUILDER_H
#define BTX_TEST_SHIELDED_RELAY_FIXTURE_BUILDER_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <limits>
#include <optional>
#include <string>

namespace Consensus {
struct Params;
} // namespace Consensus

namespace btx::test::shielded {

enum class RelayFixtureFamily : uint8_t {
    REBALANCE = 1,
    RESERVE_BOUND_SETTLEMENT_ANCHOR_RECEIPT = 2,
    EGRESS_RECEIPT = 3,
};

[[nodiscard]] std::string RelayFixtureFamilyName(RelayFixtureFamily family);

struct RelayFixtureBuildInput
{
    COutPoint funding_outpoint;
    CAmount funding_value{0};
    CScript change_script;
    CAmount fee{40'000};
};

struct RelayFixtureBuildResult
{
    CMutableTransaction tx;
    std::string family_name;
    std::optional<uint256> netting_manifest_id;
    std::optional<uint256> settlement_anchor_digest;
};

[[nodiscard]] std::optional<RelayFixtureBuildResult> BuildRelayFixtureTransaction(
    RelayFixtureFamily family,
    const RelayFixtureBuildInput& input,
    std::string& reject_reason,
    int32_t validation_height = std::numeric_limits<int32_t>::max(),
    const Consensus::Params* consensus = nullptr);

} // namespace btx::test::shielded

#endif // BTX_TEST_SHIELDED_RELAY_FIXTURE_BUILDER_H
