// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <shielded/validation.h>
#include <test/shielded_spend_path_recovery_fixture_builder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace {

BOOST_FIXTURE_TEST_SUITE(shielded_spend_path_recovery_fixture_builder_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(state_aware_fixture_builds_prefork_recovery_tx_that_validates_with_tree_snapshot)
{
    const auto& base_consensus = Params().GetConsensus();
    const int32_t activation_height = std::max<int32_t>(1, base_consensus.nShieldedMatRiCTDisableHeight - 1);

    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = activation_height;
    input.matrict_disable_height = base_consensus.nShieldedMatRiCTDisableHeight;
    input.legacy_funding_inputs.resize(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        input.legacy_funding_inputs[i].funding_outpoint =
            COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x20 + i)}), 0};
        input.legacy_funding_inputs[i].funding_value = 60'000 + static_cast<CAmount>(i) * 1'000;
    }

    std::string reject_reason;
    const auto fixture =
        btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(fixture.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(fixture->legacy_txs.size(), shielded::lattice::RING_SIZE);
    BOOST_REQUIRE_EQUAL(fixture->legacy_note_commitments.size(), shielded::lattice::RING_SIZE);
    BOOST_CHECK(!fixture->recovery_anchor.IsNull());

    shielded::ShieldedMerkleTree tree;
    for (const auto& commitment : fixture->legacy_note_commitments) {
        tree.Append(commitment);
    }
    BOOST_CHECK_EQUAL(tree.Root(), fixture->recovery_anchor);

    auto consensus = base_consensus;
    consensus.nShieldedSpendPathRecoveryActivationHeight = activation_height;

    const CTransaction tx{fixture->recovery_tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(tree),
                              nullptr,
                              nullptr);
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected spend-path recovery failure"));
}

BOOST_AUTO_TEST_CASE(state_aware_fixture_rejects_incorrect_ring_input_count)
{
    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = 1;
    input.matrict_disable_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    input.legacy_funding_inputs.resize(shielded::lattice::RING_SIZE - 1);
    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        input.legacy_funding_inputs[i].funding_outpoint =
            COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x50 + i)}), 0};
        input.legacy_funding_inputs[i].funding_value = 60'000;
    }

    std::string reject_reason;
    const auto fixture =
        btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_CHECK(!fixture.has_value());
    BOOST_CHECK_EQUAL(reject_reason,
                      "spend-path recovery fixture requires exactly one funding input per ring member");
}

BOOST_AUTO_TEST_CASE(state_aware_fixture_rejects_post_disable_validation_height)
{
    auto consensus = Params().GetConsensus();
    const int32_t post_disable_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(post_disable_height > 0);

    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = post_disable_height;
    input.matrict_disable_height = post_disable_height;
    input.legacy_funding_inputs.resize(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        input.legacy_funding_inputs[i].funding_outpoint =
            COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x70 + i)}), 0};
        input.legacy_funding_inputs[i].funding_value = 60'000;
    }

    std::string reject_reason;
    const auto fixture =
        btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_CHECK(!fixture.has_value());
    BOOST_CHECK_EQUAL(reject_reason,
                      "state-aware spend-path recovery fixture currently supports pre-disable MatRiCT heights only");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
