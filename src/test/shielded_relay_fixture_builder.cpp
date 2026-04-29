// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_relay_fixture_builder.h>

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <variant>

namespace btx::test::shielded {

namespace {

bool AttachTransparentFeeCarrier(CMutableTransaction& tx,
                                 const RelayFixtureBuildInput& input,
                                 std::string& reject_reason)
{
    if (input.funding_outpoint.IsNull()) {
        reject_reason = "missing funding outpoint";
        return false;
    }
    if (input.change_script.empty()) {
        reject_reason = "missing change script";
        return false;
    }
    if (!MoneyRange(input.funding_value) || !MoneyRange(input.fee) || input.fee <= 0) {
        reject_reason = "invalid funding amount";
        return false;
    }
    if (input.funding_value <= input.fee) {
        reject_reason = "funding amount does not cover fee";
        return false;
    }

    const CAmount change_value = input.funding_value - input.fee;
    if (!MoneyRange(change_value) || change_value <= 0) {
        reject_reason = "invalid change amount";
        return false;
    }

    tx.vin = {CTxIn{input.funding_outpoint}};
    tx.vout = {CTxOut{change_value, input.change_script}};

    TxValidationState state;
    if (!CheckTransaction(CTransaction{tx}, state)) {
        reject_reason = state.ToString();
        return false;
    }
    return true;
}

} // namespace

std::string RelayFixtureFamilyName(RelayFixtureFamily family)
{
    switch (family) {
    case RelayFixtureFamily::REBALANCE:
        return "v2_rebalance";
    case RelayFixtureFamily::RESERVE_BOUND_SETTLEMENT_ANCHOR_RECEIPT:
        return "v2_settlement_anchor";
    case RelayFixtureFamily::EGRESS_RECEIPT:
        return "v2_egress_batch";
    }
    return "unknown";
}

std::optional<RelayFixtureBuildResult> BuildRelayFixtureTransaction(
    RelayFixtureFamily family,
    const RelayFixtureBuildInput& input,
    std::string& reject_reason,
    int32_t validation_height,
    const Consensus::Params* consensus)
{
    RelayFixtureBuildResult result;
    result.family_name = RelayFixtureFamilyName(family);

    if (family == RelayFixtureFamily::REBALANCE) {
        const auto fixture = ::test::shielded::BuildV2RebalanceFixture(
            /*reserve_output_count=*/1,
            /*settlement_window=*/144,
            consensus,
            validation_height);
        result.tx = fixture.tx;
        result.netting_manifest_id = fixture.manifest_id;
    } else if (family == RelayFixtureFamily::RESERVE_BOUND_SETTLEMENT_ANCHOR_RECEIPT) {
        const auto rebalance_fixture = ::test::shielded::BuildV2RebalanceFixture(
            /*reserve_output_count=*/1,
            /*settlement_window=*/144,
            consensus,
            validation_height);
        auto fixture = ::test::shielded::BuildV2SettlementAnchorReceiptFixture(
            /*output_count=*/2,
            /*proof_receipt_count=*/1,
            /*required_receipts=*/1,
            consensus,
            validation_height);
        ::test::shielded::AttachSettlementAnchorReserveBinding(fixture.tx,
                                                               ::test::shielded::MakeSettlementAnchorReserveDeltas(),
                                                               rebalance_fixture.manifest_id);
        result.tx = fixture.tx;
        result.netting_manifest_id = rebalance_fixture.manifest_id;
        result.settlement_anchor_digest = fixture.settlement_anchor_digest;
    } else if (family == RelayFixtureFamily::EGRESS_RECEIPT) {
        const auto fixture = ::test::shielded::BuildV2EgressReceiptFixture(
            /*output_count=*/2,
            consensus,
            validation_height);
        result.tx = fixture.tx;
        const auto* bundle = result.tx.shielded_bundle.GetV2Bundle();
        if (bundle == nullptr ||
            !::shielded::v2::BundleHasSemanticFamily(*bundle,
                                                     ::shielded::v2::TransactionFamily::V2_EGRESS_BATCH)) {
            reject_reason = "failed to build v2 egress relay fixture";
            return std::nullopt;
        }
        const auto& payload = std::get<::shielded::v2::EgressBatchPayload>(bundle->payload);
        result.settlement_anchor_digest = payload.settlement_anchor;
    } else {
        reject_reason = "unsupported relay fixture family";
        return std::nullopt;
    }

    if (family != RelayFixtureFamily::EGRESS_RECEIPT &&
        !AttachTransparentFeeCarrier(result.tx, input, reject_reason)) {
        return std::nullopt;
    }

    return result;
}

} // namespace btx::test::shielded
