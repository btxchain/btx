// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chainparams.h>
#include <script/solver.h>
#include <shielded/v2_bundle.h>
#include <test/shielded_relay_fixture_builder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

CScript BuildChangeScript()
{
    return GetScriptForDestination(WitnessV2P2MR(uint256::ONE));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_relay_fixture_builder_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rebalance_fixture_builder_adds_wallet_signable_fee_carrier)
{
    std::string reject_reason;
    const auto built = btx::test::shielded::BuildRelayFixtureTransaction(
        btx::test::shielded::RelayFixtureFamily::REBALANCE,
        {
            .funding_outpoint = COutPoint{Txid::FromUint256(uint256{0x51}), 3},
            .funding_value = 10 * COIN,
            .change_script = BuildChangeScript(),
            .fee = 40'000,
        },
        reject_reason);

    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(built->family_name, "v2_rebalance");
    BOOST_CHECK_EQUAL(built->tx.vin.size(), 1U);
    BOOST_CHECK_EQUAL(built->tx.vout.size(), 1U);
    BOOST_CHECK_EQUAL(built->tx.vout[0].nValue, 10 * COIN - 40'000);
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(built->tx.vout[0].scriptPubKey, solutions) == TxoutType::WITNESS_V2_P2MR);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                      shielded::v2::TransactionFamily::V2_REBALANCE));
    const auto& payload = std::get<shielded::v2::RebalancePayload>(bundle->payload);
    BOOST_CHECK(payload.has_netting_manifest);
    BOOST_REQUIRE(built->netting_manifest_id.has_value());
    BOOST_CHECK_EQUAL(shielded::v2::ComputeNettingManifestId(payload.netting_manifest), *built->netting_manifest_id);
}

BOOST_AUTO_TEST_CASE(settlement_anchor_fixture_builder_preserves_reserve_binding)
{
    std::string reject_reason;
    const auto built = btx::test::shielded::BuildRelayFixtureTransaction(
        btx::test::shielded::RelayFixtureFamily::RESERVE_BOUND_SETTLEMENT_ANCHOR_RECEIPT,
        {
            .funding_outpoint = COutPoint{Txid::FromUint256(uint256{0x52}), 1},
            .funding_value = 9 * COIN,
            .change_script = BuildChangeScript(),
            .fee = 40'000,
        },
        reject_reason);

    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(built->family_name, "v2_settlement_anchor");
    BOOST_CHECK_EQUAL(built->tx.vin.size(), 1U);
    BOOST_CHECK_EQUAL(built->tx.vout.size(), 1U);
    BOOST_REQUIRE(built->netting_manifest_id.has_value());
    BOOST_REQUIRE(built->settlement_anchor_digest.has_value());

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                      shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR));
    const auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle->payload);
    BOOST_CHECK_EQUAL(payload.anchored_netting_manifest_id, *built->netting_manifest_id);
    BOOST_CHECK(!payload.reserve_deltas.empty());
}

BOOST_AUTO_TEST_CASE(egress_fixture_builder_preserves_settlement_anchor_without_fee_carrier)
{
    std::string reject_reason;
    const auto built = btx::test::shielded::BuildRelayFixtureTransaction(
        btx::test::shielded::RelayFixtureFamily::EGRESS_RECEIPT,
        {},
        reject_reason);

    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(built->family_name, "v2_egress_batch");
    BOOST_CHECK_EQUAL(built->tx.vin.size(), 0U);
    BOOST_CHECK_EQUAL(built->tx.vout.size(), 0U);
    BOOST_CHECK(!built->netting_manifest_id.has_value());
    BOOST_REQUIRE(built->settlement_anchor_digest.has_value());

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                      shielded::v2::TransactionFamily::V2_EGRESS_BATCH));
    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle->payload);
    BOOST_CHECK_EQUAL(payload.settlement_anchor, *built->settlement_anchor_digest);
}

BOOST_AUTO_TEST_CASE(relay_fixture_builder_rejects_missing_fee_headroom)
{
    std::string reject_reason;
    const auto built = btx::test::shielded::BuildRelayFixtureTransaction(
        btx::test::shielded::RelayFixtureFamily::REBALANCE,
        {
            .funding_outpoint = COutPoint{Txid::FromUint256(uint256{0x53}), 0},
            .funding_value = 40'000,
            .change_script = BuildChangeScript(),
            .fee = 40'000,
        },
        reject_reason);

    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "funding amount does not cover fee");
}

BOOST_AUTO_TEST_CASE(relay_fixture_builder_respects_validation_height_for_wire_family)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE_GT(activation_height, 0);

    std::string reject_reason;
    const auto prefork = btx::test::shielded::BuildRelayFixtureTransaction(
        btx::test::shielded::RelayFixtureFamily::REBALANCE,
        {
            .funding_outpoint = COutPoint{Txid::FromUint256(uint256{0x54}), 2},
            .funding_value = 10 * COIN,
            .change_script = BuildChangeScript(),
            .fee = 40'000,
        },
        reject_reason,
        activation_height - 1);
    BOOST_REQUIRE_MESSAGE(prefork.has_value(), reject_reason);

    reject_reason.clear();
    const auto postfork = btx::test::shielded::BuildRelayFixtureTransaction(
        btx::test::shielded::RelayFixtureFamily::REBALANCE,
        {
            .funding_outpoint = COutPoint{Txid::FromUint256(uint256{0x55}), 2},
            .funding_value = 10 * COIN,
            .change_script = BuildChangeScript(),
            .fee = 40'000,
        },
        reject_reason,
        activation_height);
    BOOST_REQUIRE_MESSAGE(postfork.has_value(), reject_reason);

    const auto* prefork_bundle = prefork->tx.shielded_bundle.GetV2Bundle();
    const auto* postfork_bundle = postfork->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(prefork_bundle != nullptr);
    BOOST_REQUIRE(postfork_bundle != nullptr);
    BOOST_CHECK_NE(prefork_bundle->header.family_id, postfork_bundle->header.family_id);
    BOOST_CHECK_EQUAL(
        postfork_bundle->header.family_id,
        shielded::v2::GetWireTransactionFamilyForValidationHeight(
            shielded::v2::TransactionFamily::V2_REBALANCE,
            &Params().GetConsensus(),
            activation_height));
}

BOOST_AUTO_TEST_SUITE_END()
