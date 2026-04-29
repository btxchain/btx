// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <shielded/validation.h>
#include <shielded/v2_proof.h>
#include <test/shielded_spend_path_recovery_fixture_builder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>

namespace {

BOOST_FIXTURE_TEST_SUITE(shielded_spend_path_recovery_fixture_builder_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(state_aware_fixture_builds_post_disable_recovery_tx_that_validates_with_tree_snapshot)
{
    const auto& base_consensus = Params().GetConsensus();
    const int32_t activation_height = base_consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE_GT(activation_height, 0);

    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = activation_height;
    input.matrict_disable_height = base_consensus.nShieldedMatRiCTDisableHeight;
    input.legacy_funding_inputs.resize(3);
    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        input.legacy_funding_inputs[i].funding_outpoint =
            COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x20 + i)}), 0};
        input.legacy_funding_inputs[i].funding_value = 60'000 + static_cast<CAmount>(i) * 1'000;
    }

    std::string reject_reason;
    const auto fixture =
        btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(fixture.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(fixture->legacy_txs.size(), input.legacy_funding_inputs.size());
    BOOST_REQUIRE_EQUAL(fixture->legacy_note_commitments.size(), input.legacy_funding_inputs.size());
    BOOST_CHECK(!fixture->recovery_anchor.IsNull());
    BOOST_CHECK_EQUAL(fixture->recovery_input_note_commitment, fixture->legacy_note_commitments.front());

    shielded::ShieldedMerkleTree tree;
    for (const auto& commitment : fixture->legacy_note_commitments) {
        tree.Append(commitment);
    }
    BOOST_CHECK_EQUAL(tree.Root(), fixture->recovery_anchor);

    const auto& bundle = *fixture->recovery_tx.shielded_bundle.v2_bundle;
    std::string witness_reject;
    const auto statement =
        shielded::v2::proof::DescribeSpendPathRecoveryStatement(CTransaction{fixture->recovery_tx});
    auto context =
        shielded::v2::proof::ParseSpendPathRecoveryProof(bundle, statement, witness_reject);
    BOOST_REQUIRE_MESSAGE(context.has_value(), witness_reject);
    BOOST_REQUIRE_EQUAL(context->witness.spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(context->witness.spends.front().ring_positions.size(), 1U);
    BOOST_CHECK_EQUAL(context->witness.spends.front().ring_positions.front(), 0U);

    auto consensus = base_consensus;
    consensus.nShieldedSpendPathRecoveryActivationHeight = activation_height;

    const CTransaction tx{fixture->recovery_tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              activation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>(tree),
                              nullptr,
                              std::make_shared<const std::map<uint256, uint256>>());
    const auto res = check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected spend-path recovery failure"));
}

BOOST_AUTO_TEST_CASE(state_aware_fixture_rejects_empty_funding_set)
{
    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    input.matrict_disable_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;

    std::string reject_reason;
    const auto fixture =
        btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_CHECK(!fixture.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "spend-path recovery fixture requires at least one funding input");
}

BOOST_AUTO_TEST_CASE(state_aware_fixture_rejects_pre_disable_validation_height)
{
    auto consensus = Params().GetConsensus();
    const int32_t pre_disable_height = consensus.nShieldedMatRiCTDisableHeight - 1;
    BOOST_REQUIRE(pre_disable_height > 0);

    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = pre_disable_height;
    input.matrict_disable_height = consensus.nShieldedMatRiCTDisableHeight;
    input.legacy_funding_inputs.resize(1);
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
                      "state-aware spend-path recovery fixture requires post-disable validation heights");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
