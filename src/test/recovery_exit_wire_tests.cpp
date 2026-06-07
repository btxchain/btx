// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <shielded/bundle.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_types.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <variant>
#include <vector>

namespace {

using namespace shielded::v2;

RecoveryExitPayload MakeRecoveryExitPayload()
{
    RecoveryExitPayload payload;
    payload.value = 3 * COIN;
    payload.recipient_pk_hash = uint256{0x11};
    payload.rho = uint256{0x22};
    payload.rcm = uint256{0x33};
    payload.spend_pubkey = {0x01, 0x02, 0x03, 0x04};
    payload.ownership_sig = {0x05, 0x06, 0x07, 0x08};
    payload.membership_proof = {0x09, 0x0a, 0x0b, 0x0c};
    return payload;
}

void CheckPayloadsEqual(const RecoveryExitPayload& a, const RecoveryExitPayload& b)
{
    BOOST_CHECK_EQUAL(a.version, b.version);
    BOOST_CHECK_EQUAL(a.value, b.value);
    BOOST_CHECK(a.recipient_pk_hash == b.recipient_pk_hash);
    BOOST_CHECK(a.rho == b.rho);
    BOOST_CHECK(a.rcm == b.rcm);
    BOOST_CHECK(a.spend_pubkey == b.spend_pubkey);
    BOOST_CHECK(a.ownership_sig == b.ownership_sig);
    BOOST_CHECK(a.membership_proof == b.membership_proof);
}

TransactionHeader MakeRecoveryExitHeader(const RecoveryExitPayload& payload)
{
    TransactionHeader header;
    header.family_id = TransactionFamily::V2_RECOVERY_EXIT;
    // Fork-gated OFF data layer: exercise the proof-less wire form.
    header.proof_envelope.proof_kind = ProofKind::NONE;
    header.proof_envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    header.proof_envelope.statement_digest = uint256::ZERO;
    header.payload_digest = ComputeRecoveryExitPayloadDigest(payload);
    return header;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(recovery_exit_wire_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(recovery_exit_payload_roundtrip_preserves_all_fields)
{
    const RecoveryExitPayload payload = MakeRecoveryExitPayload();
    BOOST_REQUIRE(payload.IsValid());

    DataStream ss{};
    ss << payload;

    RecoveryExitPayload decoded;
    ss >> decoded;

    BOOST_CHECK(ss.empty());
    CheckPayloadsEqual(payload, decoded);
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(ComputeRecoveryExitPayloadDigest(decoded) ==
                ComputeRecoveryExitPayloadDigest(payload));
}

BOOST_AUTO_TEST_CASE(recovery_exit_bundle_roundtrip_and_semantic_family)
{
    const RecoveryExitPayload payload = MakeRecoveryExitPayload();

    TransactionBundle bundle;
    bundle.payload = payload;
    bundle.header = MakeRecoveryExitHeader(payload);

    BOOST_REQUIRE(bundle.IsValid());
    BOOST_CHECK_EQUAL(GetPayloadFamily(bundle.payload), TransactionFamily::V2_RECOVERY_EXIT);
    BOOST_CHECK_EQUAL(GetBundleSemanticFamily(bundle), TransactionFamily::V2_RECOVERY_EXIT);
    BOOST_CHECK(BundleHasSemanticFamily(bundle, TransactionFamily::V2_RECOVERY_EXIT));

    DataStream ss{};
    ss << bundle;

    TransactionBundle decoded;
    ss >> decoded;

    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(std::holds_alternative<RecoveryExitPayload>(decoded.payload));
    BOOST_CHECK_EQUAL(GetBundleSemanticFamily(decoded), TransactionFamily::V2_RECOVERY_EXIT);
    CheckPayloadsEqual(payload, std::get<RecoveryExitPayload>(decoded.payload));
    BOOST_CHECK(ComputePayloadDigest(decoded.payload) == bundle.header.payload_digest);
    BOOST_CHECK(ComputeTransactionBundleId(decoded) == ComputeTransactionBundleId(bundle));
}

BOOST_AUTO_TEST_CASE(recovery_exit_bundle_requires_no_proof_envelope)
{
    const RecoveryExitPayload payload = MakeRecoveryExitPayload();

    TransactionBundle bundle;
    bundle.payload = payload;
    bundle.header = MakeRecoveryExitHeader(payload);
    BOOST_REQUIRE(bundle.IsValid());

    TransactionBundle with_proof = bundle;
    with_proof.header.proof_envelope.proof_kind = ProofKind::DIRECT_SMILE;
    with_proof.header.proof_envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    with_proof.header.proof_envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    with_proof.header.proof_envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    with_proof.header.proof_envelope.statement_digest = uint256{0x44};
    with_proof.proof_payload = {0x01};
    BOOST_CHECK(!with_proof.IsValid());

    TransactionBundle with_binding = bundle;
    with_binding.header.proof_envelope.settlement_binding_kind = SettlementBindingKind::GENERIC_SHIELDED;
    BOOST_CHECK(!with_binding.IsValid());
}

BOOST_AUTO_TEST_CASE(recovery_exit_state_value_balance_is_outflow_value)
{
    const RecoveryExitPayload payload = MakeRecoveryExitPayload();

    TransactionBundle bundle;
    bundle.payload = payload;
    bundle.header = MakeRecoveryExitHeader(payload);
    BOOST_REQUIRE(bundle.IsValid());

    CShieldedBundle shielded_bundle;
    shielded_bundle.v2_bundle = bundle;

    std::string reject_reason;
    const auto state_value_balance =
        TryGetShieldedStateValueBalance(shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(state_value_balance.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(*state_value_balance, payload.value);
    BOOST_CHECK_EQUAL(GetShieldedTxValueBalance(shielded_bundle), payload.value);
}

BOOST_AUTO_TEST_CASE(recovery_exit_oversize_spend_pubkey_throws_on_unserialize)
{
    RecoveryExitPayload payload = MakeRecoveryExitPayload();
    // Serialize a valid base, then hand-craft a stream whose spend_pubkey length
    // prefix exceeds MAX_RECOVERY_EXIT_PUBKEY_BYTES to confirm the bound is enforced.
    DataStream ss{};
    shielded::v2::detail::SerializeVersion(ss, payload.version, "test version");
    ::Serialize(ss, payload.value);
    ::Serialize(ss, payload.recipient_pk_hash);
    ::Serialize(ss, payload.rho);
    ::Serialize(ss, payload.rcm);
    ::Serialize(ss, COMPACTSIZE(static_cast<uint64_t>(MAX_RECOVERY_EXIT_PUBKEY_BYTES + 1)));

    RecoveryExitPayload decoded;
    BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(recovery_exit_oversize_membership_proof_throws_on_unserialize)
{
    RecoveryExitPayload payload = MakeRecoveryExitPayload();
    DataStream ss{};
    shielded::v2::detail::SerializeVersion(ss, payload.version, "test version");
    ::Serialize(ss, payload.value);
    ::Serialize(ss, payload.recipient_pk_hash);
    ::Serialize(ss, payload.rho);
    ::Serialize(ss, payload.rcm);
    shielded::v2::detail::SerializeBytes(ss, payload.spend_pubkey, MAX_RECOVERY_EXIT_PUBKEY_BYTES, "spend_pubkey");
    shielded::v2::detail::SerializeBytes(ss, payload.ownership_sig, MAX_RECOVERY_EXIT_SIGNATURE_BYTES, "ownership_sig");
    ::Serialize(ss, COMPACTSIZE(static_cast<uint64_t>(MAX_RECOVERY_EXIT_MEMBERSHIP_PROOF_BYTES + 1)));

    RecoveryExitPayload decoded;
    BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_SUITE_END()
