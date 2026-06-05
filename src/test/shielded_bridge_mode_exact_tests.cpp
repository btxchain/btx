// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Regression guard for commit ba978b75 ("consensus: enforce mode-exact attestor
// SLH-DSA on the bridge-OUT path"). Bridge-OUT attestor SLH-DSA-128S signatures
// must be verified MODE-EXACT against the validation height: FIPS-205 pure mode
// at/after the C-002 activation height, legacy round-3 (bare-hash) before it.
//
// The pre-fix bug was that the bridge-OUT settlement-anchor / egress builders
// accept either SLH-DSA scheme (VerifyBridgeBatchReceiptAnyMode), so a wrong-mode
// attestor signature could slip through the consensus path. The fix threads a
// height-exact check (shielded::VerifyBridgeBatchReceiptsModeExact) into both
// VerifyV2EgressImportedReceiptBundle and VerifyV2SettlementAnchorImportedReceiptBundle.
//
// ML-DSA-44 attestors (the fixture default) are mode-invariant — the round-3 vs
// FIPS-205 wrapper in pqkey.cpp only changes the signature for SLH_DSA_128S — so
// this guard deliberately uses SLH-DSA-128S attestors signed in a CHOSEN mode.

#include <chainparams.h>
#include <consensus/params.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <shielded/bridge.h>
#include <shielded/merkle_tree.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/v2_bundle.h>
#include <shielded/validation.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace {

// C-002 attestor SLH-DSA mode boundary (FIPS-205 at/after this height).
constexpr int64_t kC002Height = smile2::SmileCTProof::C002_ACTIVATION_HEIGHT;

// A height that is past the MatRiCT-disable (61'000) and spend-path-recovery
// (88'000) forks — so the egress bundle uses the post-fork generic wire family
// just like the post-C-002 case — but strictly BEFORE C-002 (124'000), where the
// mode-exact verifier selects the legacy round-3 scheme.
constexpr int32_t kPreC002Height = 100'000;
static_assert(kPreC002Height < kC002Height, "pre-C-002 height must precede the SLH-DSA FIPS-205 activation");

// At/after C-002 the FIPS-205 scheme applies.
constexpr int32_t kPostC002Height = static_cast<int32_t>(kC002Height);

// Run a built mode-exact hybrid egress fixture through the realistic consensus
// proof-check entry point. Egress bundles never touch the SMILE ring tree, so an
// empty tree snapshot is sufficient.
std::optional<std::string> RunEgressProofCheck(const test::shielded::V2EgressReceiptFixture& fixture,
                                               const Consensus::Params& consensus,
                                               int32_t validation_height)
{
    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              validation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>());
    return check();
}

std::optional<std::string> RunSettlementAnchorProofCheck(
    const test::shielded::V2SettlementAnchorReceiptFixture& fixture,
    const Consensus::Params& consensus,
    int32_t validation_height)
{
    const CTransaction tx{fixture.tx};
    CShieldedProofCheck check(tx,
                              consensus,
                              validation_height,
                              std::make_shared<shielded::ShieldedMerkleTree>());
    return check();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_bridge_mode_exact_tests, BasicTestingSetup)

// --- Direct unit test of the height-exact helper ---------------------------------

BOOST_AUTO_TEST_CASE(verify_mode_exact_helper_is_height_gated_for_slhdsa)
{
    const auto& consensus = Params().GetConsensus();

    // Round-3-signed SLH-DSA-128S attestor receipts.
    const auto round3_fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/false,
        &consensus,
        kPreC002Height);
    BOOST_REQUIRE(!round3_fixture.signed_receipts.empty());
    const Span<const shielded::BridgeBatchReceipt> round3_receipts{
        round3_fixture.signed_receipts.data(), round3_fixture.signed_receipts.size()};

    // FIPS-205-signed SLH-DSA-128S attestor receipts.
    const auto fips205_fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/true,
        &consensus,
        kPostC002Height);
    BOOST_REQUIRE(!fips205_fixture.signed_receipts.empty());
    const Span<const shielded::BridgeBatchReceipt> fips205_receipts{
        fips205_fixture.signed_receipts.data(), fips205_fixture.signed_receipts.size()};

    // Pre-C-002 the helper fixes the legacy round-3 scheme.
    BOOST_CHECK(!shielded::BridgeAttestorUsesFips205AtHeight(kPreC002Height));
    BOOST_CHECK(shielded::VerifyBridgeBatchReceiptsModeExact(round3_receipts, kPreC002Height));
    BOOST_CHECK(!shielded::VerifyBridgeBatchReceiptsModeExact(fips205_receipts, kPreC002Height));

    // At/after C-002 the helper fixes the FIPS-205 scheme.
    BOOST_CHECK(shielded::BridgeAttestorUsesFips205AtHeight(kC002Height));
    BOOST_CHECK(shielded::VerifyBridgeBatchReceiptsModeExact(fips205_receipts, kPostC002Height));
    BOOST_CHECK(!shielded::VerifyBridgeBatchReceiptsModeExact(round3_receipts, kPostC002Height));
}

BOOST_AUTO_TEST_CASE(mldsa_attestor_receipts_are_mode_invariant)
{
    const auto& consensus = Params().GetConsensus();

    // The same ML-DSA-44 attestor receipt verifies under BOTH "modes" and under
    // mode-exact at any height — this is exactly why the existing egress/settlement
    // tests cannot catch a mode-exactness regression, and why this guard needs
    // SLH-DSA-128S.
    const auto fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::ML_DSA_44,
        /*slhdsa_fips205=*/false,
        &consensus,
        kPostC002Height);
    BOOST_REQUIRE(!fixture.signed_receipts.empty());
    const Span<const shielded::BridgeBatchReceipt> receipts{
        fixture.signed_receipts.data(), fixture.signed_receipts.size()};

    BOOST_CHECK(shielded::VerifyBridgeBatchReceiptsModeExact(receipts, kPreC002Height));
    BOOST_CHECK(shielded::VerifyBridgeBatchReceiptsModeExact(receipts, kPostC002Height));
}

// --- Realistic consensus path: bridge-OUT egress --------------------------------

BOOST_AUTO_TEST_CASE(egress_post_c002_rejects_round3_slhdsa_attestor)
{
    const auto& consensus = Params().GetConsensus();
    const auto fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/false,
        &consensus,
        kPostC002Height);

    const auto res = RunEgressProofCheck(fixture, consensus, kPostC002Height);
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-egress-signed-receipt-mode");
}

BOOST_AUTO_TEST_CASE(egress_post_c002_accepts_fips205_slhdsa_attestor)
{
    const auto& consensus = Params().GetConsensus();
    const auto fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/true,
        &consensus,
        kPostC002Height);

    const auto res = RunEgressProofCheck(fixture, consensus, kPostC002Height);
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or(std::string{}));
}

BOOST_AUTO_TEST_CASE(egress_pre_c002_accepts_round3_slhdsa_attestor)
{
    const auto& consensus = Params().GetConsensus();
    const auto fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/false,
        &consensus,
        kPreC002Height);

    const auto res = RunEgressProofCheck(fixture, consensus, kPreC002Height);
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or(std::string{}));
}

// --- Realistic consensus path: bridge-OUT settlement-anchor ---------------------

BOOST_AUTO_TEST_CASE(settlement_anchor_post_c002_rejects_round3_slhdsa_attestor)
{
    const auto& consensus = Params().GetConsensus();
    const auto egress_fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/false,
        &consensus,
        kPostC002Height);
    auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture(egress_fixture);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = test::shielded::ResolveFixtureWireFamily(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR, &consensus, kPostC002Height);
    test::shielded::ApplyFixtureWireEnvelopeKinds(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        bundle->header.proof_envelope,
        &consensus,
        kPostC002Height);
    BOOST_REQUIRE(bundle->IsValid());

    const auto res = RunSettlementAnchorProofCheck(fixture, consensus, kPostC002Height);
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-settlement-anchor-signed-receipt-mode");
}

BOOST_AUTO_TEST_CASE(settlement_anchor_post_c002_accepts_fips205_slhdsa_attestor)
{
    const auto& consensus = Params().GetConsensus();
    const auto egress_fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/true,
        &consensus,
        kPostC002Height);
    auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture(egress_fixture);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = test::shielded::ResolveFixtureWireFamily(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR, &consensus, kPostC002Height);
    test::shielded::ApplyFixtureWireEnvelopeKinds(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        bundle->header.proof_envelope,
        &consensus,
        kPostC002Height);
    BOOST_REQUIRE(bundle->IsValid());

    const auto res = RunSettlementAnchorProofCheck(fixture, consensus, kPostC002Height);
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or(std::string{}));
}

BOOST_AUTO_TEST_CASE(settlement_anchor_pre_c002_accepts_round3_slhdsa_attestor)
{
    const auto& consensus = Params().GetConsensus();
    const auto egress_fixture = test::shielded::BuildV2EgressModeExactHybridReceiptFixture(
        PQAlgorithm::SLH_DSA_128S,
        /*slhdsa_fips205=*/false,
        &consensus,
        kPreC002Height);
    auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture(egress_fixture);
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);
    bundle->header.family_id = test::shielded::ResolveFixtureWireFamily(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR, &consensus, kPreC002Height);
    test::shielded::ApplyFixtureWireEnvelopeKinds(
        shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR,
        bundle->header.proof_envelope,
        &consensus,
        kPreC002Height);
    BOOST_REQUIRE(bundle->IsValid());

    const auto res = RunSettlementAnchorProofCheck(fixture, consensus, kPreC002Height);
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or(std::string{}));
}

BOOST_AUTO_TEST_SUITE_END()
