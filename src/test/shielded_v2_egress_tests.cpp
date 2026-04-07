// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_egress.h>
#include <shielded/v2_send.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace v2proof = shielded::v2::proof;

template <size_t N>
std::array<uint8_t, N> DeriveSeed(std::string_view tag, uint32_t index)
{
    std::array<uint8_t, N> seed{};
    size_t offset{0};
    uint32_t counter{0};
    while (offset < seed.size()) {
        HashWriter hw;
        hw << std::string{tag} << index << counter;
        const uint256 digest = hw.GetSHA256();
        const size_t copy_len = std::min(seed.size() - offset, static_cast<size_t>(uint256::size()));
        std::copy_n(digest.begin(), copy_len, seed.begin() + offset);
        offset += copy_len;
        ++counter;
    }
    return seed;
}

ShieldedNote MakeNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(note.IsValid());
    return note;
}

mlkem::KeyPair BuildKeyPair(std::string_view tag, uint32_t index)
{
    return mlkem::KeyGenDerand(DeriveSeed<mlkem::KEYGEN_SEEDBYTES>(tag, index));
}

shielded::EncryptedNote EncryptNote(const ShieldedNote& note,
                                    const mlkem::PublicKey& recipient_pk,
                                    uint32_t index)
{
    return shielded::NoteEncryption::EncryptDeterministic(
        note,
        recipient_pk,
        DeriveSeed<mlkem::ENCAPS_SEEDBYTES>("BTX_ShieldedV2_Egress_KEM", index),
        DeriveSeed<12>("BTX_ShieldedV2_Egress_Nonce", index));
}

shielded::v2::OutputDescription BuildOutput(const ShieldedNote& note,
                                            const mlkem::PublicKey& recipient_pk,
                                            unsigned char seed)
{
    const shielded::EncryptedNote encrypted_note =
        EncryptNote(note, recipient_pk, static_cast<uint32_t>(seed));
    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(encrypted_note,
                                                                  recipient_pk,
                                                                  shielded::v2::ScanDomain::BATCH);
    BOOST_REQUIRE(payload.has_value());

    shielded::v2::OutputDescription output;
    output.note_class = shielded::v2::NoteClass::USER;
    auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    BOOST_REQUIRE(smile_account.has_value());
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
    output.value_commitment = uint256{seed};
    output.smile_account = std::move(*smile_account);
    output.encrypted_note = *payload;
    BOOST_REQUIRE(output.IsValid());
    return output;
}

void CanonicalizeOutputsForStatement(std::vector<shielded::v2::OutputDescription>& outputs,
                                     shielded::BridgeBatchStatement& statement)
{
    const uint256 output_binding_digest = shielded::v2::ComputeV2EgressOutputBindingDigest(statement);
    BOOST_REQUIRE(!output_binding_digest.IsNull());
    for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
        outputs[output_index].value_commitment = shielded::v2::ComputeV2EgressOutputValueCommitment(
            output_binding_digest,
            static_cast<uint32_t>(output_index),
            outputs[output_index].note_commitment);
    }
    statement.batch_root = shielded::v2::ComputeOutputDescriptionRoot(
        Span<const shielded::v2::OutputDescription>{outputs.data(), outputs.size()});
}

shielded::v2::V2EgressBuildInput BuildInput(std::vector<shielded::v2::OutputDescription> outputs)
{
    BOOST_REQUIRE(!outputs.empty());

    shielded::v2::V2EgressBuildInput input;
    input.imported_descriptor.proof_system_id = uint256{0x91};
    input.imported_descriptor.verifier_key_hash = uint256{0x92};
    input.proof_descriptors = {input.imported_descriptor};

    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(input.proof_descriptors,
                                                                   /*required_receipts=*/1);
    BOOST_REQUIRE(proof_policy.has_value());

    input.statement.direction = shielded::BridgeDirection::BRIDGE_OUT;
    input.statement.ids.bridge_id = uint256{0x81};
    input.statement.ids.operation_id = uint256{0x82};
    input.statement.entry_count = static_cast<uint32_t>(outputs.size());
    input.statement.total_amount = 7 * COIN + 9 * COIN + 11 * COIN;
    input.statement.domain_id = uint256{0x83};
    input.statement.source_epoch = 9;
    input.statement.data_root = uint256{0x84};
    input.statement.proof_policy = *proof_policy;
    input.statement.version = 3;
    CanonicalizeOutputsForStatement(outputs, input.statement);
    const auto aggregate_commitment = shielded::BuildDefaultBridgeBatchAggregateCommitment(
        input.statement.batch_root,
        input.statement.data_root,
        input.statement.proof_policy);
    BOOST_REQUIRE(aggregate_commitment.has_value());
    input.statement.aggregate_commitment = *aggregate_commitment;
    input.statement.version = 5;
    BOOST_REQUIRE(input.statement.IsValid());
    BOOST_CHECK(input.statement.aggregate_commitment.action_root == input.statement.batch_root);
    BOOST_CHECK(input.statement.aggregate_commitment.data_availability_root == input.statement.data_root);

    input.imported_receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(input.statement);
    input.imported_receipt.proof_system_id = input.imported_descriptor.proof_system_id;
    input.imported_receipt.verifier_key_hash = input.imported_descriptor.verifier_key_hash;
    input.imported_receipt.public_values_hash = uint256{0x85};
    input.imported_receipt.proof_commitment = uint256{0x86};
    BOOST_REQUIRE(input.imported_receipt.IsValid());

    input.proof_receipts = {input.imported_receipt};
    input.outputs = std::move(outputs);
    input.output_chunk_sizes = {2, 1};
    BOOST_REQUIRE(input.IsValid());
    return input;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_v2_egress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(build_v2_egress_statement_derives_deterministic_output_root)
{
    const mlkem::KeyPair recipient_a = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 21);
    const mlkem::KeyPair recipient_b = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 22);

    std::vector<shielded::v2::V2EgressRecipient> recipients;
    recipients.push_back({uint256{0x21}, recipient_a.pk, 13 * COIN});
    recipients.push_back({uint256{0x22}, recipient_b.pk, 17 * COIN});

    std::vector<shielded::BridgeProofDescriptor> descriptors;
    descriptors.push_back({uint256{0x31}, uint256{0x32}});
    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
        Span<const shielded::BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        /*required_receipts=*/1);
    BOOST_REQUIRE(proof_policy.has_value());

    shielded::v2::V2EgressStatementTemplate statement_template;
    statement_template.ids.bridge_id = uint256{0x41};
    statement_template.ids.operation_id = uint256{0x42};
    statement_template.domain_id = uint256{0x43};
    statement_template.source_epoch = 11;
    statement_template.data_root = uint256{0x44};
    statement_template.proof_policy = *proof_policy;

    std::string reject_reason;
    auto statement = shielded::v2::BuildV2EgressStatement(
        statement_template,
        Span<const shielded::v2::V2EgressRecipient>{recipients.data(), recipients.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(statement.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(statement->version, 5U);
    BOOST_CHECK_EQUAL(statement->entry_count, recipients.size());
    BOOST_CHECK_EQUAL(statement->total_amount, 30 * COIN);
    BOOST_CHECK(statement->aggregate_commitment.action_root == statement->batch_root);
    BOOST_CHECK(statement->aggregate_commitment.data_availability_root == statement->data_root);

    auto outputs = shielded::v2::BuildDeterministicEgressOutputs(
        *statement,
        Span<const shielded::v2::V2EgressRecipient>{recipients.data(), recipients.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(outputs.has_value(), reject_reason);
    const uint256 output_root = shielded::v2::ComputeOutputDescriptionRoot(
        Span<const shielded::v2::OutputDescription>{outputs->data(), outputs->size()});
    BOOST_CHECK(statement->batch_root == output_root);

    auto second_outputs = shielded::v2::BuildDeterministicEgressOutputs(
        *statement,
        Span<const shielded::v2::V2EgressRecipient>{recipients.data(), recipients.size()},
        reject_reason);
    BOOST_REQUIRE(second_outputs.has_value());
    BOOST_CHECK_EQUAL(second_outputs->size(), outputs->size());
    for (size_t i = 0; i < outputs->size(); ++i) {
        BOOST_REQUIRE((*outputs)[i].smile_account.has_value());
        BOOST_CHECK(smile2::ComputeCompactPublicAccountHash(*(*outputs)[i].smile_account) ==
                    (*outputs)[i].note_commitment);
        BOOST_CHECK((*outputs)[i].note_commitment == (*second_outputs)[i].note_commitment);
        BOOST_CHECK((*outputs)[i].encrypted_note.ciphertext == (*second_outputs)[i].encrypted_note.ciphertext);
        BOOST_CHECK((*outputs)[i].encrypted_note.scan_hint == (*second_outputs)[i].encrypted_note.scan_hint);
    }
}

BOOST_AUTO_TEST_CASE(v2_egress_output_binding_digest_ignores_future_proofed_wrapper_version)
{
    const mlkem::KeyPair recipient_a = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 31);
    const mlkem::KeyPair recipient_b = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 32);

    std::vector<shielded::v2::V2EgressRecipient> recipients;
    recipients.push_back({uint256{0x71}, recipient_a.pk, 5 * COIN});
    recipients.push_back({uint256{0x72}, recipient_b.pk, 6 * COIN});

    std::vector<shielded::BridgeProofDescriptor> descriptors;
    descriptors.push_back({uint256{0x73}, uint256{0x74}});
    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
        Span<const shielded::BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        /*required_receipts=*/1);
    BOOST_REQUIRE(proof_policy.has_value());

    shielded::v2::V2EgressStatementTemplate statement_template;
    statement_template.ids.bridge_id = uint256{0x75};
    statement_template.ids.operation_id = uint256{0x76};
    statement_template.domain_id = uint256{0x77};
    statement_template.source_epoch = 12;
    statement_template.data_root = uint256{0x78};
    statement_template.proof_policy = *proof_policy;

    std::string reject_reason;
    auto final_statement = shielded::v2::BuildV2EgressStatement(
        statement_template,
        Span<const shielded::v2::V2EgressRecipient>{recipients.data(), recipients.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(final_statement.has_value(), reject_reason);
    BOOST_CHECK_EQUAL(final_statement->version, 5U);

    auto legacy_binding_statement = *final_statement;
    legacy_binding_statement.version = 3;
    legacy_binding_statement.aggregate_commitment = {};

    BOOST_CHECK(shielded::v2::ComputeV2EgressOutputBindingDigest(*final_statement) ==
                shielded::v2::ComputeV2EgressOutputBindingDigest(legacy_binding_statement));
}

BOOST_AUTO_TEST_CASE(build_v2_egress_transaction_matches_contextual_verifier)
{
    const mlkem::KeyPair recipient_a = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 1);
    const mlkem::KeyPair recipient_b = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 2);
    const mlkem::KeyPair recipient_c = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 3);

    const ShieldedNote note_a = MakeNote(7 * COIN, 0x31);
    const ShieldedNote note_b = MakeNote(9 * COIN, 0x41);
    const ShieldedNote note_c = MakeNote(11 * COIN, 0x51);
    const std::vector<shielded::v2::OutputDescription> outputs{
        BuildOutput(note_a, recipient_a.pk, 0x61),
        BuildOutput(note_b, recipient_b.pk, 0x62),
        BuildOutput(note_c, recipient_c.pk, 0x63),
    };

    auto input = BuildInput(outputs);

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 27;

    std::string reject_reason;
    auto built = shielded::v2::BuildV2EgressBatchTransaction(tx_template, input, reject_reason);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK(built->IsValid());
    BOOST_CHECK(reject_reason.empty());

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(bundle->IsValid());
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                      shielded::v2::TransactionFamily::V2_EGRESS_BATCH));

    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), outputs.size());
    BOOST_CHECK(payload.egress_root == input.statement.batch_root);
    BOOST_CHECK_EQUAL(bundle->output_chunks.size(), 2U);
    BOOST_CHECK_EQUAL(bundle->output_chunks[0].output_count, 2U);
    BOOST_CHECK_EQUAL(bundle->output_chunks[1].output_count, 1U);

    const auto anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(input.statement,
                                                                             input.proof_receipts);
    BOOST_REQUIRE(anchor.has_value());
    BOOST_CHECK(payload.settlement_anchor == v2proof::ComputeSettlementExternalAnchorDigest(*anchor));
    BOOST_CHECK(payload.settlement_binding_digest ==
                shielded::ComputeBridgeProofReceiptHash(input.imported_receipt));

    auto parsed_witness = v2proof::ParseSettlementWitness(bundle->proof_payload, reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_witness.has_value(), reject_reason);
    auto parsed_receipt = v2proof::ParseImportedSettlementReceipt(bundle->header.proof_envelope,
                                                                  bundle->proof_shards.front(),
                                                                  reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_receipt.has_value(), reject_reason);
    auto context = v2proof::DescribeImportedSettlementReceipt(*parsed_receipt,
                                                              v2proof::PayloadLocation::INLINE_WITNESS,
                                                              bundle->proof_payload,
                                                              input.imported_descriptor);
    BOOST_CHECK(v2proof::VerifySettlementContext(context, *parsed_witness, reject_reason));
}

BOOST_AUTO_TEST_CASE(postfork_egress_builder_uses_generic_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    const mlkem::KeyPair recipient_a = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 31);
    const mlkem::KeyPair recipient_b = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 32);
    const mlkem::KeyPair recipient_c = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 33);
    const std::vector<shielded::v2::OutputDescription> outputs{
        BuildOutput(MakeNote(7 * COIN, 0x91), recipient_a.pk, 0xa1),
        BuildOutput(MakeNote(9 * COIN, 0x92), recipient_b.pk, 0xa2),
        BuildOutput(MakeNote(11 * COIN, 0x93), recipient_c.pk, 0xa3),
    };

    auto input = BuildInput(outputs);
    input.output_chunk_sizes.clear();
    std::string reject_reason;
    auto built = shielded::v2::BuildV2EgressBatchTransaction(CMutableTransaction{},
                                                             input,
                                                             reject_reason,
                                                             &consensus,
                                                             activation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                      shielded::v2::TransactionFamily::V2_EGRESS_BATCH));
    BOOST_REQUIRE_EQUAL(bundle->output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(bundle->output_chunks.front().output_count, outputs.size());

    auto parsed_witness = v2proof::ParseSettlementWitness(bundle->proof_payload, reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_witness.has_value(), reject_reason);
    auto parsed_receipt = v2proof::ParseImportedSettlementReceipt(bundle->header.proof_envelope,
                                                                  bundle->proof_shards.front(),
                                                                  reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_receipt.has_value(), reject_reason);

    v2proof::SettlementContext context;
    context.material.statement.domain = v2proof::VerificationDomain::BATCH_SETTLEMENT;
    context.material.statement.envelope = bundle->header.proof_envelope;
    context.material.payload_location = v2proof::PayloadLocation::INLINE_WITNESS;
    context.material.proof_shards = bundle->proof_shards;
    context.material.proof_payload = bundle->proof_payload;
    context.imported_receipt = *parsed_receipt;
    context.descriptor =
        shielded::BridgeProofDescriptor{parsed_receipt->proof_system_id, parsed_receipt->verifier_key_hash};
    BOOST_REQUIRE(context.IsValid());
    BOOST_CHECK(v2proof::VerifySettlementContext(context, *parsed_witness, reject_reason));
}

BOOST_AUTO_TEST_CASE(postfork_egress_builder_rejects_explicit_output_chunk_partition)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    const mlkem::KeyPair recipient_a = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 41);
    const mlkem::KeyPair recipient_b = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 42);
    const mlkem::KeyPair recipient_c = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 43);
    const std::vector<shielded::v2::OutputDescription> outputs{
        BuildOutput(MakeNote(7 * COIN, 0xb1), recipient_a.pk, 0xc1),
        BuildOutput(MakeNote(9 * COIN, 0xb2), recipient_b.pk, 0xc2),
        BuildOutput(MakeNote(11 * COIN, 0xb3), recipient_c.pk, 0xc3),
    };

    auto input = BuildInput(outputs);
    BOOST_REQUIRE_EQUAL(input.output_chunk_sizes.size(), 2U);

    std::string reject_reason;
    auto built = shielded::v2::BuildV2EgressBatchTransaction(CMutableTransaction{},
                                                             input,
                                                             reject_reason,
                                                             &consensus,
                                                             activation_height);
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-egress-builder-chunks");
}

BOOST_AUTO_TEST_CASE(build_v2_egress_transaction_rejects_output_root_mismatch)
{
    const mlkem::KeyPair recipient_a = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 11);
    const mlkem::KeyPair recipient_b = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 12);
    const mlkem::KeyPair recipient_c = BuildKeyPair("BTX_ShieldedV2_Egress_Recipient", 13);

    const std::vector<shielded::v2::OutputDescription> outputs{
        BuildOutput(MakeNote(7 * COIN, 0x71), recipient_a.pk, 0x81),
        BuildOutput(MakeNote(9 * COIN, 0x72), recipient_b.pk, 0x82),
        BuildOutput(MakeNote(11 * COIN, 0x73), recipient_c.pk, 0x83),
    };

    auto input = BuildInput(outputs);
    input.statement.batch_root = uint256{0xaa};

    std::string reject_reason;
    auto built = shielded::v2::BuildV2EgressBatchTransaction(CMutableTransaction{}, input, reject_reason);
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-egress-builder-outputs");
}

BOOST_AUTO_TEST_CASE(build_v2_egress_transaction_matches_hybrid_contextual_verifier)
{
    const auto fixture = test::shielded::BuildV2EgressHybridReceiptFixture();
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto parsed_witness = v2proof::ParseSettlementWitness(bundle->proof_payload, reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_witness.has_value(), reject_reason);
    auto parsed_receipt = v2proof::ParseImportedSettlementReceipt(bundle->header.proof_envelope,
                                                                  bundle->proof_shards.front(),
                                                                  reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_receipt.has_value(), reject_reason);
    BOOST_REQUIRE(fixture.verification_bundle.has_value());

    auto context = v2proof::DescribeImportedSettlementReceipt(*parsed_receipt,
                                                              v2proof::PayloadLocation::INLINE_WITNESS,
                                                              bundle->proof_payload,
                                                              fixture.descriptor,
                                                              fixture.verification_bundle);
    BOOST_REQUIRE(context.IsValid());
    BOOST_CHECK(v2proof::VerifySettlementContext(context, *parsed_witness, reject_reason));

    const auto anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(
        fixture.statement,
        Span<const shielded::BridgeBatchReceipt>{fixture.signed_receipts.data(), fixture.signed_receipts.size()},
        Span<const shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                 fixture.witness.proof_receipts.size()});
    BOOST_REQUIRE(anchor.has_value());
    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle->payload);
    BOOST_CHECK(payload.settlement_anchor == v2proof::ComputeSettlementExternalAnchorDigest(*anchor));
}

BOOST_AUTO_TEST_CASE(build_v2_egress_transaction_matches_multi_receipt_hybrid_contextual_verifier)
{
    const auto fixture = test::shielded::BuildV2EgressHybridReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto parsed_witness = v2proof::ParseSettlementWitness(bundle->proof_payload, reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(parsed_witness->proof_receipts.size(), 2U);
    BOOST_CHECK_EQUAL(parsed_witness->statement.proof_policy.required_receipts, 2U);
    auto parsed_receipt = v2proof::ParseImportedSettlementReceipt(bundle->header.proof_envelope,
                                                                  bundle->proof_shards.front(),
                                                                  reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_receipt.has_value(), reject_reason);
    BOOST_REQUIRE(fixture.verification_bundle.has_value());

    auto context = v2proof::DescribeImportedSettlementReceipt(*parsed_receipt,
                                                              v2proof::PayloadLocation::INLINE_WITNESS,
                                                              bundle->proof_payload,
                                                              fixture.descriptor,
                                                              fixture.verification_bundle);
    BOOST_REQUIRE(context.IsValid());
    BOOST_CHECK(v2proof::VerifySettlementContext(context, *parsed_witness, reject_reason));

    const auto anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(
        fixture.statement,
        Span<const shielded::BridgeBatchReceipt>{fixture.signed_receipts.data(), fixture.signed_receipts.size()},
        Span<const shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                 fixture.witness.proof_receipts.size()});
    BOOST_REQUIRE(anchor.has_value());
    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle->payload);
    BOOST_CHECK(payload.settlement_anchor == v2proof::ComputeSettlementExternalAnchorDigest(*anchor));
}

BOOST_AUTO_TEST_CASE(build_v2_egress_transaction_matches_multi_receipt_contextual_verifier)
{
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);
    const auto* bundle = fixture.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto parsed_witness = v2proof::ParseSettlementWitness(bundle->proof_payload, reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(parsed_witness->proof_receipts.size(), 2U);
    BOOST_CHECK_EQUAL(parsed_witness->statement.proof_policy.required_receipts, 2U);

    auto parsed_receipt = v2proof::ParseImportedSettlementReceipt(bundle->header.proof_envelope,
                                                                  bundle->proof_shards.front(),
                                                                  reject_reason);
    BOOST_REQUIRE_MESSAGE(parsed_receipt.has_value(), reject_reason);

    auto context = v2proof::DescribeImportedSettlementReceipt(*parsed_receipt,
                                                              v2proof::PayloadLocation::INLINE_WITNESS,
                                                              bundle->proof_payload,
                                                              fixture.descriptor);
    BOOST_REQUIRE(context.IsValid());
    BOOST_CHECK(v2proof::VerifySettlementContext(context, *parsed_witness, reject_reason));

    const auto anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(
        fixture.statement,
        Span<const shielded::BridgeProofReceipt>{fixture.witness.proof_receipts.data(),
                                                 fixture.witness.proof_receipts.size()});
    BOOST_REQUIRE(anchor.has_value());
    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle->payload);
    BOOST_CHECK(payload.settlement_anchor == v2proof::ComputeSettlementExternalAnchorDigest(*anchor));
}

BOOST_AUTO_TEST_SUITE_END()
