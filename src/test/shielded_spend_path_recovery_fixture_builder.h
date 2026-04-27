// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_SPEND_PATH_RECOVERY_FIXTURE_BUILDER_H
#define BTX_TEST_SHIELDED_SPEND_PATH_RECOVERY_FIXTURE_BUILDER_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace btx::test::shielded {

struct SpendPathRecoveryFundingInput
{
    COutPoint funding_outpoint;
    CAmount funding_value{0};
};

struct SpendPathRecoveryFixtureBuildInput
{
    std::vector<SpendPathRecoveryFundingInput> legacy_funding_inputs;
    CAmount legacy_shield_fee{1000};
    CAmount recovery_fee{1000};
    unsigned char seed_base{0x61};
    int32_t validation_height{1};
    int32_t matrict_disable_height{132};
};

struct SpendPathRecoveryFixtureBuildResult
{
    std::vector<CMutableTransaction> legacy_txs;
    std::vector<uint256> legacy_note_commitments;
    CMutableTransaction recovery_tx;
    uint256 legacy_anchor;
    uint256 recovery_anchor;
    uint256 recovery_input_note_commitment;
    uint256 recovery_output_note_commitment;
};

[[nodiscard]] std::optional<SpendPathRecoveryFixtureBuildResult> BuildSpendPathRecoveryFixture(
    const SpendPathRecoveryFixtureBuildInput& input,
    std::string& reject_reason);

} // namespace btx::test::shielded

#endif // BTX_TEST_SHIELDED_SPEND_PATH_RECOVERY_FIXTURE_BUILDER_H
