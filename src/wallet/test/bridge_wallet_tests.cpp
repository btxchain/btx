// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <key_io.h>
#include <pqkey.h>
#include <shielded/bridge.h>
#include <shielded/view_grant.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <wallet/bridge_wallet.h>
#include <wallet/shielded_privacy.h>

#include <algorithm>
#include <string>
#include <utility>

#include <boost/test/unit_test.hpp>

namespace wallet {
namespace {

shielded::BridgeKeySpec MakeBridgeKey(unsigned char seed, PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);
    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));
    return {algo, key.GetPubKey()};
}

mlkem::KeyPair MakeKEMKey(unsigned char seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> material{};
    material.fill(seed);
    return mlkem::KeyGenDerand(material);
}

ShieldedAddress MakeShieldedAddress(unsigned char spend_seed, unsigned char kem_seed)
{
    ShieldedAddress address;
    const auto spend = MakeBridgeKey(spend_seed);
    const auto kem = MakeKEMKey(kem_seed);
    HashWriter hw;
    hw.write(AsBytes(Span<const unsigned char>{spend.pubkey.data(), spend.pubkey.size()}));
    address.version = 0x01;
    address.algo_byte = 0x00;
    address.pk_hash = hw.GetSHA256();
    std::copy(kem.pk.begin(), kem.pk.end(), address.kem_pk.begin());
    HashWriter kem_hw;
    kem_hw.write(AsBytes(Span<const uint8_t>{kem.pk.data(), kem.pk.size()}));
    address.kem_pk_hash = kem_hw.GetSHA256();
    BOOST_REQUIRE(address.IsValid());
    return address;
}

struct BridgeAuditPayloadV1
{
    uint8_t version{0};
    uint256 note_commitment;
    uint256 recipient_pk_hash;
    CAmount value{0};
    uint256 rho;
    uint256 rcm;

    SERIALIZE_METHODS(BridgeAuditPayloadV1, obj)
    {
        READWRITE(obj.version, obj.note_commitment, obj.recipient_pk_hash, obj.value, obj.rho, obj.rcm);
    }
};

BridgeInPlanRequest MakeBridgeInRequest()
{
    BridgeInPlanRequest request;
    request.ids.bridge_id = uint256{100};
    request.ids.operation_id = uint256{200};
    request.operator_key = MakeBridgeKey(0x11);
    request.refund_key = MakeBridgeKey(0x22, PQAlgorithm::SLH_DSA_128S);
    request.recipient = MakeShieldedAddress(0x33, 0x44);
    request.shielded_anchor = uint256{55};
    request.amount = 5 * COIN;
    request.refund_lock_height = 720;
    request.build_height = 1;
    request.memo = {'b', 'r', 'i', 'd', 'g', 'e'};
    return request;
}

BridgeOutPlanRequest MakeBridgeOutRequest()
{
    BridgeOutPlanRequest request;
    request.ids.bridge_id = uint256{30};
    request.ids.operation_id = uint256{40};
    request.operator_key = MakeBridgeKey(0x55);
    request.refund_key = MakeBridgeKey(0x66);
    request.genesis_hash = uint256{77};
    request.payout = CTxOut{4 * COIN, GetScriptForDestination(WitnessV2P2MR(uint256{88}))};
    request.refund_lock_height = 1440;
    return request;
}

shielded::BridgeBatchCommitment MakeBatchCommitment(shielded::BridgeDirection direction, CAmount total_amount)
{
    std::vector<shielded::BridgeBatchLeaf> leaves;
    shielded::BridgeBatchLeaf a;
    a.kind = shielded::BridgeBatchLeafKind::SHIELD_CREDIT;
    a.wallet_id = uint256{40};
    a.destination_id = uint256{41};
    a.amount = total_amount / 2;
    a.authorization_hash = uint256{42};
    leaves.push_back(a);

    shielded::BridgeBatchLeaf b = a;
    b.wallet_id = uint256{50};
    b.destination_id = uint256{51};
    b.amount = total_amount - a.amount;
    b.authorization_hash = uint256{52};
    leaves.push_back(b);

    shielded::BridgeBatchCommitment commitment;
    commitment.direction = direction;
    commitment.ids.bridge_id = uint256{90};
    commitment.ids.operation_id = uint256{91};
    commitment.entry_count = leaves.size();
    commitment.total_amount = total_amount;
    commitment.batch_root = shielded::ComputeBridgeBatchRoot(leaves);
    return commitment;
}

shielded::BridgeExternalAnchor MakeExternalAnchor()
{
    shielded::BridgeExternalAnchor anchor;
    anchor.domain_id = uint256{0xa0};
    anchor.source_epoch = 9;
    anchor.data_root = uint256{0xa1};
    anchor.verification_root = uint256{0xa2};
    return anchor;
}

shielded::BridgeBatchCommitment MakeFutureProofedBatchCommitment(shielded::BridgeDirection direction,
                                                                 CAmount total_amount)
{
    auto commitment = MakeBatchCommitment(direction, total_amount);
    commitment.external_anchor = MakeExternalAnchor();
    const auto aggregate_commitment = shielded::BuildDefaultBridgeBatchAggregateCommitment(
        commitment.batch_root,
        commitment.external_anchor.data_root,
        shielded::BridgeProofPolicyCommitment{});
    BOOST_REQUIRE(aggregate_commitment.has_value());
    commitment.aggregate_commitment = *aggregate_commitment;
    commitment.version = 3;
    BOOST_REQUIRE(commitment.IsValid());
    return commitment;
}

BridgePlan RoundTripBridgePlan(const BridgePlan& plan)
{
    DataStream ss{};
    ss << plan;
    BridgePlan decoded;
    ss >> decoded;
    BOOST_REQUIRE(ss.empty());
    return decoded;
}

std::optional<CViewGrant::SecureBytes> DecryptBridgePlanViewGrant(const BridgePlan& plan,
                                                                  size_t grant_index,
                                                                  const mlkem::SecretKey& operator_sk)
{
    BOOST_REQUIRE_LT(grant_index, plan.view_grant_metadata.size());
    BOOST_REQUIRE_LT(grant_index, plan.shielded_bundle.view_grants.size());
    const std::vector<uint8_t> metadata_aad = SerializeBridgeViewGrantMetadataAad(
        plan.view_grant_metadata[grant_index]);
    BOOST_REQUIRE(!metadata_aad.empty());
    return plan.shielded_bundle.view_grants[grant_index].DecryptWithAad(
        operator_sk,
        Span<const uint8_t>{metadata_aad.data(), metadata_aad.size()});
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bridge_wallet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bridge_in_plan_contains_two_valid_control_paths)
{
    const auto plan = BuildBridgeInPlan(MakeBridgeInRequest());
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK(plan->kind == shielded::BridgeTemplateKind::SHIELD);
    BOOST_CHECK(plan->script_tree.IsValid());
    BOOST_CHECK_EQUAL(plan->shielded_bundle.shielded_outputs.size(), 1U);
}

BOOST_AUTO_TEST_CASE(bridge_out_plan_contains_csfs_attestation_payload)
{
    const auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK(plan->kind == shielded::BridgeTemplateKind::UNSHIELD);
    BOOST_CHECK(plan->has_attestation);
    const auto attestation_bytes = shielded::SerializeBridgeAttestationMessage(plan->attestation);
    BOOST_CHECK(!attestation_bytes.empty());
    BOOST_CHECK(!shielded::ComputeBridgeAttestationHash(plan->attestation).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_inserts_operator_view_grants_when_operator_kem_keys_present)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x99);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::LEGACY_AUDIT, operator_kem.pk, 0});

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.view_grants.size(), 1U);

    const auto decrypted = DecryptBridgePlanViewGrant(*plan, 0, operator_kem.sk);
    BOOST_REQUIRE(decrypted.has_value());
    DataStream ds{Span<const uint8_t>{decrypted->data(), decrypted->size()}};
    BridgeAuditPayloadV1 payload;
    ds >> payload;
    BOOST_CHECK_EQUAL(payload.version, 1U);
    BOOST_CHECK_EQUAL(payload.value, request.amount);
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_supports_structured_operator_view_grants)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x9a);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
                                            operator_kem.pk,
                                            static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                                 shielded::viewgrants::DISCLOSE_RECIPIENT |
                                                                 shielded::viewgrants::DISCLOSE_SENDER)});

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.view_grants.size(), 1U);

    const auto decrypted = DecryptBridgePlanViewGrant(*plan, 0, operator_kem.sk);
    BOOST_REQUIRE(decrypted.has_value());
    const auto payload = shielded::viewgrants::DecodeStructuredDisclosurePayload(
        Span<const uint8_t>{decrypted->data(), decrypted->size()});
    BOOST_REQUIRE(payload.has_value());
    BOOST_CHECK_EQUAL(payload->disclosure_flags,
                      static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                           shielded::viewgrants::DISCLOSE_RECIPIENT |
                                           shielded::viewgrants::DISCLOSE_SENDER));
    BOOST_CHECK_EQUAL(payload->amount, request.amount);
    BOOST_CHECK(payload->recipient_pk_hash == request.recipient.pk_hash);
    BOOST_CHECK(payload->memo.empty());
    BOOST_CHECK(payload->sender.bridge_id == request.ids.bridge_id);
    BOOST_CHECK(payload->sender.operation_id == request.ids.operation_id);
}

BOOST_AUTO_TEST_CASE(bridge_plan_serializes_view_grant_policy_metadata)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0xa2);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
                                            operator_kem.pk,
                                            static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                                 shielded::viewgrants::DISCLOSE_SENDER)});
    request.disclosure_policy = BridgeDisclosurePolicy{
        1,
        10 * COIN,
        {{BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
          operator_kem.pk,
          shielded::viewgrants::DISCLOSE_RECIPIENT}}};

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK_EQUAL(plan->version, BridgePlan::VIEW_GRANT_POLICY_VERSION);
    BOOST_REQUIRE_EQUAL(plan->view_grant_metadata.size(), 1U);
    BOOST_CHECK_EQUAL(plan->view_grant_metadata[0].format, BridgeViewGrantFormat::STRUCTURED_DISCLOSURE);
    BOOST_CHECK_EQUAL(plan->view_grant_metadata[0].disclosure_flags,
                      static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                           shielded::viewgrants::DISCLOSE_SENDER));
    BOOST_REQUIRE(plan->disclosure_policy.has_value());

    const BridgePlan decoded = RoundTripBridgePlan(*plan);
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.version, BridgePlan::VIEW_GRANT_POLICY_VERSION);
    BOOST_REQUIRE_EQUAL(decoded.view_grant_metadata.size(), 1U);
    BOOST_CHECK(decoded.view_grant_metadata[0].recipient_pubkey == operator_kem.pk);
    BOOST_CHECK_EQUAL(decoded.view_grant_metadata[0].format, BridgeViewGrantFormat::STRUCTURED_DISCLOSURE);
    BOOST_CHECK_EQUAL(decoded.view_grant_metadata[0].disclosure_flags,
                      static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                           shielded::viewgrants::DISCLOSE_SENDER));
    BOOST_REQUIRE(decoded.disclosure_policy.has_value());
    BOOST_CHECK_EQUAL(decoded.disclosure_policy->threshold_amount, 10 * COIN);
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_supports_max_structured_view_grants)
{
    auto request = MakeBridgeInRequest();
    std::vector<mlkem::KeyPair> operators;
    operators.reserve(MAX_VIEW_GRANTS_PER_TX);
    for (size_t i = 0; i < MAX_VIEW_GRANTS_PER_TX; ++i) {
        operators.push_back(MakeKEMKey(static_cast<unsigned char>(0xb0 + i)));
        request.operator_view_grants.push_back({
            BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
            operators.back().pk,
            static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                 shielded::viewgrants::DISCLOSE_RECIPIENT |
                                 shielded::viewgrants::DISCLOSE_SENDER)});
    }

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.view_grants.size(), MAX_VIEW_GRANTS_PER_TX);
    BOOST_REQUIRE_EQUAL(plan->view_grant_metadata.size(), MAX_VIEW_GRANTS_PER_TX);

    for (size_t i = 0; i < plan->shielded_bundle.view_grants.size(); ++i) {
        bool decrypted_by_expected_operator{false};
        for (const auto& op : operators) {
            const auto decrypted = DecryptBridgePlanViewGrant(*plan, i, op.sk);
            if (!decrypted.has_value()) continue;
            const auto payload = shielded::viewgrants::DecodeStructuredDisclosurePayload(
                Span<const uint8_t>{decrypted->data(), decrypted->size()});
            BOOST_REQUIRE(payload.has_value());
            BOOST_CHECK_EQUAL(payload->amount, request.amount);
            BOOST_CHECK(payload->recipient_pk_hash == request.recipient.pk_hash);
            decrypted_by_expected_operator = true;
            break;
        }
        BOOST_CHECK(decrypted_by_expected_operator);
    }
}

BOOST_AUTO_TEST_CASE(bridge_plan_rejects_noncanonical_view_grant_metadata)
{
    auto request = MakeBridgeInRequest();
    const auto first_operator_kem = MakeKEMKey(0xb1);
    const auto second_operator_kem = MakeKEMKey(0xb2);
    request.operator_view_grants = {
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, second_operator_kem.pk, shielded::viewgrants::DISCLOSE_SENDER},
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, first_operator_kem.pk, shielded::viewgrants::DISCLOSE_AMOUNT},
    };

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->view_grant_metadata.size(), 2U);
    BOOST_REQUIRE(plan->IsValid());

    BridgePlan reordered = *plan;
    std::swap(reordered.view_grant_metadata[0], reordered.view_grant_metadata[1]);
    BOOST_CHECK(!reordered.IsValid());
    BOOST_CHECK(!CreateBridgeShieldSettlementTransaction(
        reordered,
        COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0xb1)}), 0},
        -reordered.shielded_bundle.value_balance + 2000,
        &Params().GetConsensus(),
        Params().GetConsensus().nShieldedMatRiCTDisableHeight).has_value());

    BridgePlan duplicate = *plan;
    duplicate.view_grant_metadata[1] = duplicate.view_grant_metadata[0];
    BOOST_CHECK(!duplicate.IsValid());
}

BOOST_AUTO_TEST_CASE(bridge_plan_rejects_view_grant_format_ciphertext_size_mismatch)
{
    auto structured_request = MakeBridgeInRequest();
    const auto structured_operator_kem = MakeKEMKey(0xb3);
    structured_request.operator_view_grants.push_back(
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
         structured_operator_kem.pk,
         static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                              shielded::viewgrants::DISCLOSE_RECIPIENT |
                              shielded::viewgrants::DISCLOSE_SENDER)});

    const auto structured_plan = BuildBridgeInPlan(structured_request);
    BOOST_REQUIRE(structured_plan.has_value());
    BridgePlan forged_legacy = *structured_plan;
    forged_legacy.view_grant_metadata[0].format = BridgeViewGrantFormat::LEGACY_AUDIT;
    forged_legacy.view_grant_metadata[0].disclosure_flags = 0;
    BOOST_CHECK(!forged_legacy.IsValid());

    auto legacy_request = MakeBridgeInRequest();
    const auto legacy_operator_kem = MakeKEMKey(0xb4);
    legacy_request.operator_view_grants.push_back({BridgeViewGrantFormat::LEGACY_AUDIT, legacy_operator_kem.pk, 0});
    legacy_request.allow_legacy_audit_view_grants = true;

    const auto legacy_plan = BuildBridgeInPlan(legacy_request);
    BOOST_REQUIRE(legacy_plan.has_value());
    BridgePlan forged_structured = *legacy_plan;
    forged_structured.view_grant_metadata[0].format = BridgeViewGrantFormat::STRUCTURED_DISCLOSURE;
    forged_structured.view_grant_metadata[0].disclosure_flags =
        static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                             shielded::viewgrants::DISCLOSE_RECIPIENT |
                             shielded::viewgrants::DISCLOSE_SENDER);
    BOOST_CHECK(!forged_structured.IsValid());
}

BOOST_AUTO_TEST_CASE(bridge_plan_rejects_structured_memo_grant_with_legacy_audit_ciphertext_size)
{
    auto legacy_request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0xb5);
    legacy_request.operator_view_grants.push_back({BridgeViewGrantFormat::LEGACY_AUDIT, operator_kem.pk, 0});
    legacy_request.allow_legacy_audit_view_grants = true;

    const auto legacy_plan = BuildBridgeInPlan(legacy_request);
    BOOST_REQUIRE(legacy_plan.has_value());
    BOOST_REQUIRE_EQUAL(legacy_plan->view_grant_metadata.size(), 1U);

    BridgePlan forged_structured_memo = *legacy_plan;
    forged_structured_memo.allow_legacy_audit_view_grants = false;
    forged_structured_memo.view_grant_metadata[0].format = BridgeViewGrantFormat::STRUCTURED_DISCLOSURE;
    forged_structured_memo.view_grant_metadata[0].disclosure_flags =
        static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                             shielded::viewgrants::DISCLOSE_RECIPIENT |
                             shielded::viewgrants::DISCLOSE_MEMO |
                             shielded::viewgrants::DISCLOSE_SENDER);
    BOOST_CHECK(!forged_structured_memo.IsValid());
}

BOOST_AUTO_TEST_CASE(bridge_shield_settlement_rejects_unclassified_v1_view_grants_postfork)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0xa3);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::LEGACY_AUDIT, operator_kem.pk, 0});

    auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    plan->version = BridgePlan::LEGACY_VERSION;
    plan->view_grant_metadata.clear();
    plan->allow_legacy_audit_view_grants = false;
    plan->disclosure_policy.reset();
    BOOST_REQUIRE(plan->IsValid());

    const int32_t postfork_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(UseShieldedPrivacyRedesignAtHeight(postfork_height));
    const auto error = ValidateBridgePlanViewGrantPolicy(*plan, postfork_height);
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK(error->find("without serialized view-grant policy metadata") != std::string::npos);

    const auto psbt = CreateBridgeShieldSettlementTransaction(
        *plan,
        COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0xa4)}), 0},
        -plan->shielded_bundle.value_balance + 2000,
        &Params().GetConsensus(),
        postfork_height);
    BOOST_CHECK(!psbt.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_shield_settlement_requires_legacy_view_grant_opt_in_postfork)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0xa5);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::LEGACY_AUDIT, operator_kem.pk, 0});

    auto rejected_plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(rejected_plan.has_value());
    BOOST_REQUIRE_EQUAL(rejected_plan->view_grant_metadata.size(), 1U);
    BOOST_CHECK_EQUAL(rejected_plan->view_grant_metadata[0].format, BridgeViewGrantFormat::LEGACY_AUDIT);
    BOOST_CHECK(!rejected_plan->allow_legacy_audit_view_grants);

    const int32_t postfork_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(UseShieldedPrivacyRedesignAtHeight(postfork_height));
    const auto error = ValidateBridgePlanViewGrantPolicy(*rejected_plan, postfork_height);
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK(error->find("allow_legacy_audit_view_grants=true") != std::string::npos);
    BOOST_CHECK(!CreateBridgeShieldSettlementTransaction(
        *rejected_plan,
        COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0xa6)}), 0},
        -rejected_plan->shielded_bundle.value_balance + 2000,
        &Params().GetConsensus(),
        postfork_height).has_value());

    request.allow_legacy_audit_view_grants = true;
    const auto accepted_plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(accepted_plan.has_value());
    BOOST_CHECK(accepted_plan->allow_legacy_audit_view_grants);
    BOOST_CHECK(ValidateBridgePlanViewGrantPolicy(*accepted_plan, postfork_height).has_value());
    BOOST_CHECK(!ValidateBridgePlanViewGrantPolicy(
        *accepted_plan,
        postfork_height,
        /*allow_legacy_audit_view_grants=*/true).has_value());
    BOOST_CHECK(!CreateBridgeShieldSettlementTransaction(
        *accepted_plan,
        COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0xa7)}), 0},
        -accepted_plan->shielded_bundle.value_balance + 2000,
        &Params().GetConsensus(),
        postfork_height).has_value());
    BOOST_CHECK(CreateBridgeShieldSettlementTransaction(
        *accepted_plan,
        COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0xa7)}), 0},
        -accepted_plan->shielded_bundle.value_balance + 2000,
        &Params().GetConsensus(),
        postfork_height,
        /*allow_legacy_audit_view_grants=*/true).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_structured_operator_view_grant_rejects_wrong_operator_key)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x9e);
    const auto wrong_operator_kem = MakeKEMKey(0x9f);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
                                            operator_kem.pk,
                                            static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                                 shielded::viewgrants::DISCLOSE_RECIPIENT |
                                                                 shielded::viewgrants::DISCLOSE_SENDER)});

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.view_grants.size(), 1U);

    BOOST_CHECK(!DecryptBridgePlanViewGrant(*plan, 0, wrong_operator_kem.sk).has_value());

    const auto decrypted = DecryptBridgePlanViewGrant(*plan, 0, operator_kem.sk);
    BOOST_REQUIRE(decrypted.has_value());
    const auto payload = shielded::viewgrants::DecodeStructuredDisclosurePayload(
        Span<const uint8_t>{decrypted->data(), decrypted->size()});
    BOOST_REQUIRE(payload.has_value());
    BOOST_CHECK_EQUAL(payload->amount, request.amount);
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_operator_view_grants_use_fresh_encryption_randomness)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0xa1);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
                                            operator_kem.pk,
                                            static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                                 shielded::viewgrants::DISCLOSE_RECIPIENT |
                                                                 shielded::viewgrants::DISCLOSE_SENDER)});

    const auto first = BuildBridgeInPlan(request);
    const auto second = BuildBridgeInPlan(request);
    BOOST_REQUIRE(first.has_value());
    BOOST_REQUIRE(second.has_value());
    BOOST_REQUIRE_EQUAL(first->shielded_bundle.view_grants.size(), 1U);
    BOOST_REQUIRE_EQUAL(second->shielded_bundle.view_grants.size(), 1U);

    const auto& first_grant = first->shielded_bundle.view_grants[0];
    const auto& second_grant = second->shielded_bundle.view_grants[0];
    BOOST_CHECK(first_grant.kem_ct != second_grant.kem_ct ||
                first_grant.nonce != second_grant.nonce ||
                first_grant.encrypted_data != second_grant.encrypted_data);

    const auto first_decrypted = DecryptBridgePlanViewGrant(*first, 0, operator_kem.sk);
    const auto second_decrypted = DecryptBridgePlanViewGrant(*second, 0, operator_kem.sk);
    BOOST_REQUIRE(first_decrypted.has_value());
    BOOST_REQUIRE(second_decrypted.has_value());
    BOOST_CHECK(*first_decrypted == *second_decrypted);
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_structured_operator_view_grant_rejects_tampering)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0xa0);
    request.operator_view_grants.push_back({BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
                                            operator_kem.pk,
                                            static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                                 shielded::viewgrants::DISCLOSE_RECIPIENT |
                                                                 shielded::viewgrants::DISCLOSE_SENDER)});

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.view_grants.size(), 1U);
    const auto& grant = plan->shielded_bundle.view_grants[0];

    const std::vector<uint8_t> metadata_aad = SerializeBridgeViewGrantMetadataAad(plan->view_grant_metadata[0]);
    BOOST_REQUIRE(!metadata_aad.empty());
    BOOST_CHECK(!grant.Decrypt(operator_kem.sk).has_value());

    auto wrong_metadata = plan->view_grant_metadata[0];
    wrong_metadata.disclosure_flags = shielded::viewgrants::DISCLOSE_AMOUNT;
    const std::vector<uint8_t> wrong_metadata_aad = SerializeBridgeViewGrantMetadataAad(wrong_metadata);
    BOOST_REQUIRE(!wrong_metadata_aad.empty());
    BOOST_CHECK(!grant.DecryptWithAad(
        operator_kem.sk,
        Span<const uint8_t>{wrong_metadata_aad.data(), wrong_metadata_aad.size()}).has_value());

    const auto decrypted = grant.DecryptWithAad(
        operator_kem.sk,
        Span<const uint8_t>{metadata_aad.data(), metadata_aad.size()});
    BOOST_REQUIRE(decrypted.has_value());
    const auto payload = shielded::viewgrants::DecodeStructuredDisclosurePayload(
        Span<const uint8_t>{decrypted->data(), decrypted->size()});
    BOOST_REQUIRE(payload.has_value());
    BOOST_CHECK_EQUAL(payload->amount, request.amount);

    CViewGrant tampered_encrypted_data{grant};
    BOOST_REQUIRE(!tampered_encrypted_data.encrypted_data.empty());
    tampered_encrypted_data.encrypted_data[0] ^= 0x01;
    BOOST_CHECK(!tampered_encrypted_data.DecryptWithAad(
        operator_kem.sk,
        Span<const uint8_t>{metadata_aad.data(), metadata_aad.size()}).has_value());

    CViewGrant tampered_nonce{grant};
    tampered_nonce.nonce[0] ^= 0x01;
    BOOST_CHECK(!tampered_nonce.DecryptWithAad(
        operator_kem.sk,
        Span<const uint8_t>{metadata_aad.data(), metadata_aad.size()}).has_value());

    CViewGrant tampered_kem_ciphertext{grant};
    tampered_kem_ciphertext.kem_ct[0] ^= 0x01;
    BOOST_CHECK(!tampered_kem_ciphertext.DecryptWithAad(
        operator_kem.sk,
        Span<const uint8_t>{metadata_aad.data(), metadata_aad.size()}).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_omits_view_grants_when_not_requested)
{
    const auto plan = BuildBridgeInPlan(MakeBridgeInRequest());
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK(plan->shielded_bundle.view_grants.empty());
}

BOOST_AUTO_TEST_CASE(bridge_disclosure_policy_adds_required_grants_when_threshold_is_met)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x9b);
    request.disclosure_policy = BridgeDisclosurePolicy{
        1,
        3 * COIN,
        {{BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
          operator_kem.pk,
          static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT | shielded::viewgrants::DISCLOSE_RECIPIENT)}}};

    const auto error = ValidateAndApplyBridgeDisclosurePolicy(request);
    BOOST_CHECK(!error.has_value());
    BOOST_REQUIRE_EQUAL(request.operator_view_grants.size(), 1U);
    BOOST_CHECK_EQUAL(request.operator_view_grants[0].format, BridgeViewGrantFormat::STRUCTURED_DISCLOSURE);
    BOOST_CHECK_EQUAL(request.operator_view_grants[0].disclosure_flags,
                      static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                           shielded::viewgrants::DISCLOSE_RECIPIENT));

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK_EQUAL(plan->shielded_bundle.view_grants.size(), 1U);
}

BOOST_AUTO_TEST_CASE(bridge_shield_settlement_reenforces_serialized_disclosure_policy_metadata)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x9a);
    request.disclosure_policy = BridgeDisclosurePolicy{
        1,
        3 * COIN,
        {{BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
          operator_kem.pk,
          static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT | shielded::viewgrants::DISCLOSE_RECIPIENT)}}};

    auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->view_grant_metadata.size(), 1U);

    const int32_t postfork_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_CHECK(!ValidateBridgePlanViewGrantPolicy(*plan, postfork_height).has_value());

    plan->disclosure_policy->required_grants[0].disclosure_flags =
        static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                             shielded::viewgrants::DISCLOSE_RECIPIENT |
                             shielded::viewgrants::DISCLOSE_SENDER);
    BOOST_REQUIRE(plan->IsValid());
    const auto error = ValidateBridgePlanViewGrantPolicy(*plan, postfork_height);
    BOOST_REQUIRE(error.has_value());
    BOOST_CHECK(error->find("disclosure_policy required grant is missing") != std::string::npos);
    BOOST_CHECK(!CreateBridgeShieldSettlementTransaction(
        *plan,
        COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x9a)}), 0},
        -plan->shielded_bundle.value_balance + 2000,
        &Params().GetConsensus(),
        postfork_height).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_disclosure_policy_is_ignored_below_threshold)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x9c);
    request.amount = COIN;
    request.disclosure_policy = BridgeDisclosurePolicy{
        1,
        2 * COIN,
        {{BridgeViewGrantFormat::STRUCTURED_DISCLOSURE,
          operator_kem.pk,
          static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT)}}};

    const auto error = ValidateAndApplyBridgeDisclosurePolicy(request);
    BOOST_CHECK(!error.has_value());
    BOOST_CHECK(request.operator_view_grants.empty());

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK(plan->shielded_bundle.view_grants.empty());
}

BOOST_AUTO_TEST_CASE(bridge_disclosure_policy_merges_duplicate_structured_grants)
{
    auto request = MakeBridgeInRequest();
    const auto operator_kem = MakeKEMKey(0x9d);
    request.operator_view_grants = {
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, operator_kem.pk, shielded::viewgrants::DISCLOSE_AMOUNT},
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, operator_kem.pk, shielded::viewgrants::DISCLOSE_RECIPIENT},
    };

    const auto error = ValidateAndApplyBridgeDisclosurePolicy(request);
    BOOST_CHECK(!error.has_value());
    BOOST_REQUIRE_EQUAL(request.operator_view_grants.size(), 1U);
    BOOST_CHECK_EQUAL(request.operator_view_grants[0].disclosure_flags,
                      static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                           shielded::viewgrants::DISCLOSE_RECIPIENT));
}

BOOST_AUTO_TEST_CASE(bridge_disclosure_policy_canonicalizes_resolved_grant_order)
{
    auto request = MakeBridgeInRequest();
    const auto first_operator_kem = MakeKEMKey(0x9e);
    const auto second_operator_kem = MakeKEMKey(0x9f);
    request.operator_view_grants = {
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, second_operator_kem.pk, shielded::viewgrants::DISCLOSE_SENDER},
        {BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, first_operator_kem.pk, shielded::viewgrants::DISCLOSE_AMOUNT},
    };
    auto expected = request.operator_view_grants;
    std::sort(expected.begin(), expected.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.format != rhs.format) {
            return static_cast<uint8_t>(lhs.format) < static_cast<uint8_t>(rhs.format);
        }
        if (!std::equal(lhs.recipient_pubkey.begin(), lhs.recipient_pubkey.end(), rhs.recipient_pubkey.begin())) {
            return std::lexicographical_compare(lhs.recipient_pubkey.begin(),
                                                lhs.recipient_pubkey.end(),
                                                rhs.recipient_pubkey.begin(),
                                                rhs.recipient_pubkey.end());
        }
        return lhs.disclosure_flags < rhs.disclosure_flags;
    });

    const auto error = ValidateAndApplyBridgeDisclosurePolicy(request);
    BOOST_CHECK(!error.has_value());
    BOOST_REQUIRE_EQUAL(request.operator_view_grants.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_CHECK_EQUAL(request.operator_view_grants[i].format, expected[i].format);
        BOOST_CHECK(request.operator_view_grants[i].recipient_pubkey == expected[i].recipient_pubkey);
        BOOST_CHECK_EQUAL(request.operator_view_grants[i].disclosure_flags, expected[i].disclosure_flags);
    }
}

BOOST_AUTO_TEST_CASE(bridge_disclosure_policy_rejects_invalid_entries)
{
    auto request = MakeBridgeInRequest();
    request.disclosure_policy = BridgeDisclosurePolicy{
        1,
        COIN,
        {{BridgeViewGrantFormat::STRUCTURED_DISCLOSURE, mlkem::PublicKey{}, shielded::viewgrants::DISCLOSE_AMOUNT}}};

    const auto error = ValidateAndApplyBridgeDisclosurePolicy(request);
    BOOST_REQUIRE(error.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_refund_transaction_selects_refund_leaf)
{
    const auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    const auto psbt = CreateBridgeRefundTransaction(*plan,
                                                    COutPoint{Txid::FromUint256(uint256{123}), 0},
                                                    5 * COIN,
                                                    WitnessV2P2MR(uint256{124}),
                                                    1000);
    BOOST_REQUIRE(psbt.has_value());
    BOOST_CHECK(psbt->tx->nLockTime == plan->refund_lock_height);
    BOOST_CHECK(psbt->tx->vin[0].nSequence == CTxIn::MAX_SEQUENCE_NONFINAL);
    BOOST_CHECK(psbt->inputs[0].m_p2mr_leaf_script == plan->script_tree.refund_leaf_script);
}

BOOST_AUTO_TEST_CASE(bridge_refund_transaction_rounds_postfork_fee_bucket)
{
    const auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    constexpr CAmount prev_value = 5 * COIN;
    constexpr CAmount requested_fee = 1501;
    const CAmount rounded_fee =
        shielded::RoundShieldedFeeToCanonicalBucket(requested_fee, Params().GetConsensus(), 61000);

    const auto psbt = CreateBridgeRefundTransaction(*plan,
                                                    COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0xd2)}), 0},
                                                    prev_value,
                                                    WitnessV2P2MR(uint256{static_cast<unsigned char>(0xdc)}),
                                                    requested_fee,
                                                    &Params().GetConsensus(),
                                                    61000);
    BOOST_REQUIRE(psbt.has_value());
    BOOST_REQUIRE_EQUAL(psbt->tx->vout.size(), 1U);
    BOOST_CHECK_EQUAL(psbt->tx->vout[0].nValue, prev_value - rounded_fee);
}

BOOST_AUTO_TEST_CASE(bridge_unshield_settlement_populates_selected_p2mr_leaf_and_csfs_message)
{
    const auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    const auto psbt = CreateBridgeUnshieldSettlementTransaction(*plan,
                                                                COutPoint{Txid::FromUint256(uint256{222}), 0},
                                                                5 * COIN);
    BOOST_REQUIRE(psbt.has_value());
    BOOST_CHECK(psbt->inputs[0].m_p2mr_leaf_script == plan->script_tree.normal_leaf_script);
    BOOST_CHECK(psbt->inputs[0].m_p2mr_control_block == plan->script_tree.normal_control_block);
    BOOST_CHECK_EQUAL(psbt->inputs[0].m_p2mr_csfs_msgs.size(), 1U);
}

BOOST_AUTO_TEST_CASE(bridge_plan_generation_reuses_existing_psbt_csfs_fields)
{
    const auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    const auto psbt = CreateBridgeUnshieldSettlementTransaction(*plan,
                                                                COutPoint{Txid::FromUint256(uint256{33}), 0},
                                                                5 * COIN);
    BOOST_REQUIRE(psbt.has_value());
    BOOST_CHECK(psbt->inputs[0].unknown.empty());
    BOOST_CHECK(psbt->inputs[0].m_proprietary.empty());
    BOOST_CHECK(!psbt->inputs[0].m_p2mr_csfs_msgs.empty());
}

BOOST_AUTO_TEST_CASE(bridge_shield_settlement_rejects_ctv_hash_mismatch)
{
    auto plan = BuildBridgeInPlan(MakeBridgeInRequest());
    BOOST_REQUIRE(plan.has_value());
    plan->ctv_hash = uint256{0xaa};

    const auto psbt = CreateBridgeShieldSettlementTransaction(*plan,
                                                              COutPoint{Txid::FromUint256(uint256{0xbb}), 0},
                                                              6 * COIN);
    BOOST_CHECK(!psbt.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_shield_settlement_rejects_postfork_noncanonical_fee)
{
    auto plan = BuildBridgeInPlan(MakeBridgeInRequest());
    BOOST_REQUIRE(plan.has_value());

    const auto rejected = CreateBridgeShieldSettlementTransaction(*plan,
                                                                  COutPoint{Txid::FromUint256(uint256{0xbc}), 0},
                                                                  plan->shielded_bundle.value_balance * -1 + 1501,
                                                                  &Params().GetConsensus(),
                                                                  61000);
    BOOST_CHECK(!rejected.has_value());

    const auto accepted = CreateBridgeShieldSettlementTransaction(*plan,
                                                                  COutPoint{Txid::FromUint256(uint256{0xbd}), 0},
                                                                  plan->shielded_bundle.value_balance * -1 + 2000,
                                                                  &Params().GetConsensus(),
                                                                  61000);
    BOOST_CHECK(accepted.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_unshield_settlement_rejects_ctv_hash_mismatch)
{
    auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    plan->ctv_hash = uint256{0xcc};

    const auto psbt = CreateBridgeUnshieldSettlementTransaction(*plan,
                                                                COutPoint{Txid::FromUint256(uint256{0xdd}), 0},
                                                                5 * COIN);
    BOOST_CHECK(!psbt.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_unshield_settlement_rejects_postfork_noncanonical_fee)
{
    auto plan = BuildBridgeOutPlan(MakeBridgeOutRequest());
    BOOST_REQUIRE(plan.has_value());
    const auto outputs_total = plan->transparent_outputs.front().nValue;

    const auto rejected = CreateBridgeUnshieldSettlementTransaction(*plan,
                                                                    COutPoint{Txid::FromUint256(uint256{0xde}), 0},
                                                                    outputs_total + 1501,
                                                                    &Params().GetConsensus(),
                                                                    61000);
    BOOST_CHECK(!rejected.has_value());

    const auto accepted = CreateBridgeUnshieldSettlementTransaction(*plan,
                                                                    COutPoint{Txid::FromUint256(uint256{0xdf}), 0},
                                                                    outputs_total + 2000,
                                                                    &Params().GetConsensus(),
                                                                    61000);
    BOOST_CHECK(accepted.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_plan_rejects_mismatched_operator_and_refund_keys)
{
    auto request = MakeBridgeInRequest();
    request.operator_key.pubkey = {0x01, 0x02};
    BOOST_CHECK(!BuildBridgeInPlan(request).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_uses_canonical_batch_commitment_as_note_memo)
{
    auto request = MakeBridgeInRequest();
    request.ids.bridge_id = uint256{90};
    request.ids.operation_id = uint256{91};
    request.memo.clear();
    request.batch_commitment = MakeBatchCommitment(shielded::BridgeDirection::BRIDGE_IN, request.amount);

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.shielded_outputs.size(), 1U);

    const auto memo_bytes = shielded::SerializeBridgeBatchCommitment(*request.batch_commitment);
    BOOST_CHECK(!memo_bytes.empty());
    BOOST_CHECK_EQUAL(memo_bytes.size(), 110U);
}

BOOST_AUTO_TEST_CASE(bridge_out_plan_supports_multi_payout_batch_attestation)
{
    auto request = MakeBridgeOutRequest();
    request.ids.bridge_id = uint256{90};
    request.ids.operation_id = uint256{91};
    request.payouts = {
        CTxOut{2 * COIN, GetScriptForDestination(WitnessV2P2MR(uint256{91}))},
        CTxOut{2 * COIN, GetScriptForDestination(WitnessV2P2MR(uint256{92}))}};
    request.batch_commitment = MakeBatchCommitment(shielded::BridgeDirection::BRIDGE_OUT, 4 * COIN);

    const auto plan = BuildBridgeOutPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK_EQUAL(plan->transparent_outputs.size(), 2U);
    BOOST_CHECK_EQUAL(plan->attestation.version, 2U);
    BOOST_CHECK_EQUAL(plan->attestation.batch_entry_count, request.batch_commitment->entry_count);
    BOOST_CHECK_EQUAL(plan->attestation.batch_total_amount, request.batch_commitment->total_amount);
    BOOST_CHECK(plan->attestation.batch_root == request.batch_commitment->batch_root);
}

BOOST_AUTO_TEST_CASE(bridge_in_plan_supports_external_anchor_in_batch_commitment_memo)
{
    auto request = MakeBridgeInRequest();
    request.ids.bridge_id = uint256{90};
    request.ids.operation_id = uint256{91};
    request.memo.clear();
    request.batch_commitment = MakeFutureProofedBatchCommitment(shielded::BridgeDirection::BRIDGE_IN, request.amount);

    const auto plan = BuildBridgeInPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_REQUIRE_EQUAL(plan->shielded_bundle.shielded_outputs.size(), 1U);

    const auto memo_bytes = shielded::SerializeBridgeBatchCommitment(*request.batch_commitment);
    BOOST_CHECK(!memo_bytes.empty());
    const auto decoded = shielded::DeserializeBridgeBatchCommitment(Span<const unsigned char>{memo_bytes.data(), memo_bytes.size()});
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 3U);
    BOOST_CHECK(decoded->aggregate_commitment.action_root == request.batch_commitment->aggregate_commitment.action_root);
    BOOST_CHECK(decoded->aggregate_commitment.data_availability_root ==
                request.batch_commitment->aggregate_commitment.data_availability_root);
}

BOOST_AUTO_TEST_CASE(bridge_out_plan_carries_external_anchor_into_v3_attestation)
{
    auto request = MakeBridgeOutRequest();
    request.ids.bridge_id = uint256{90};
    request.ids.operation_id = uint256{91};
    request.payouts = {
        CTxOut{2 * COIN, GetScriptForDestination(WitnessV2P2MR(uint256{91}))},
        CTxOut{2 * COIN, GetScriptForDestination(WitnessV2P2MR(uint256{92}))}};
    request.batch_commitment = MakeFutureProofedBatchCommitment(shielded::BridgeDirection::BRIDGE_OUT, 4 * COIN);

    const auto plan = BuildBridgeOutPlan(request);
    BOOST_REQUIRE(plan.has_value());
    BOOST_CHECK_EQUAL(plan->attestation.version, 3U);
    BOOST_CHECK(plan->attestation.external_anchor.domain_id == request.batch_commitment->external_anchor.domain_id);
    BOOST_CHECK_EQUAL(plan->attestation.external_anchor.source_epoch, request.batch_commitment->external_anchor.source_epoch);
    BOOST_CHECK(plan->attestation.external_anchor.data_root == request.batch_commitment->external_anchor.data_root);
    BOOST_CHECK(plan->attestation.external_anchor.verification_root == request.batch_commitment->external_anchor.verification_root);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
