// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_spend_path_recovery_fixture_builder.h>

#include <consensus/params.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <shielded/account_registry.h>
#include <shielded/lattice/params.h>
#include <shielded/note_encryption.h>
#include <shielded/ringct/matrict.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>
#include <streams.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <util/check.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace btx::test::shielded {
namespace {

namespace sh = ::shielded;
using namespace ::shielded::ringct;
namespace v2proof = ::shielded::v2::proof;

template <size_t N>
[[nodiscard]] std::array<uint8_t, N> FilledArray(unsigned char value)
{
    std::array<uint8_t, N> out{};
    out.fill(value);
    return out;
}

[[nodiscard]] ShieldedNote MakeLegacyNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    return note;
}

[[nodiscard]] ShieldedNote MakeLegacyNote(CAmount value,
                                          const uint256& recipient_pk_hash,
                                          unsigned char seed)
{
    ShieldedNote note = MakeLegacyNote(value, seed);
    note.recipient_pk_hash = recipient_pk_hash;
    return note;
}

[[nodiscard]] mlkem::KeyPair BuildRecipientKeyPair(unsigned char seed)
{
    return mlkem::KeyGenDerand(FilledArray<mlkem::KEYGEN_SEEDBYTES>(seed));
}

[[nodiscard]] sh::EncryptedNote EncryptLegacyNote(const ShieldedNote& note,
                                                  const mlkem::PublicKey& recipient_pk,
                                                  unsigned char seed)
{
    return sh::NoteEncryption::EncryptDeterministic(
        note,
        recipient_pk,
        FilledArray<mlkem::ENCAPS_SEEDBYTES>(seed),
        FilledArray<12>(static_cast<unsigned char>(seed + 1)));
}

[[nodiscard]] sh::v2::OutputDescription BuildRecoveryOutput(const ShieldedNote& note,
                                                            const mlkem::PublicKey& recipient_pk,
                                                            unsigned char seed,
                                                            std::string& reject_reason)
{
    auto encoded_note = sh::v2::EncodeLegacyEncryptedNotePayload(
        EncryptLegacyNote(note, recipient_pk, seed),
        recipient_pk,
        sh::v2::ScanDomain::OPAQUE);
    if (!encoded_note.has_value()) {
        reject_reason = "failed to encode spend-path recovery output payload";
        return {};
    }

    sh::v2::OutputDescription output;
    output.note_class = sh::v2::NoteClass::USER;
    output.smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    if (!output.smile_account.has_value()) {
        reject_reason = "failed to build spend-path recovery smile account";
        return {};
    }
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    output.encrypted_note = *encoded_note;
    if (!output.IsValid()) {
        reject_reason = "invalid spend-path recovery output";
        return {};
    }
    return output;
}

[[nodiscard]] std::optional<CMutableTransaction> BuildUnsignedLegacyShieldOnlyTx(
    const SpendPathRecoveryFundingInput& funding_input,
    const uint256& legacy_anchor,
    const ShieldedNote& note,
    const mlkem::PublicKey& recipient_kem_pk,
    unsigned char seed,
    CAmount fee,
    std::string& reject_reason)
{
    if (funding_input.funding_outpoint.IsNull()) {
        reject_reason = "missing legacy funding outpoint";
        return std::nullopt;
    }
    if (!MoneyRange(funding_input.funding_value) || funding_input.funding_value <= fee) {
        reject_reason = "invalid legacy funding amount";
        return std::nullopt;
    }
    if (legacy_anchor.IsNull()) {
        reject_reason = "missing legacy shield anchor";
        return std::nullopt;
    }

    CMutableTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.nLockTime = seed;
    tx.vin = {CTxIn{funding_input.funding_outpoint}};

    CShieldedOutput output;
    output.note_commitment = note.GetCommitment();
    output.encrypted_note = EncryptLegacyNote(note, recipient_kem_pk, seed);
    output.merkle_anchor = legacy_anchor;
    tx.shielded_bundle.shielded_outputs.push_back(std::move(output));
    tx.shielded_bundle.value_balance = -(funding_input.funding_value - fee);
    return tx;
}

[[nodiscard]] bool ApplyRecoveryWireEnvelope(sh::v2::TransactionBundle& bundle,
                                             const Consensus::Params* consensus,
                                             int32_t validation_height)
{
    using namespace ::shielded::v2;

    bundle.header.family_id = GetWireTransactionFamilyForValidationHeight(
        V2_SPEND_PATH_RECOVERY,
        consensus,
        validation_height);
    bundle.header.proof_envelope.proof_kind = GetWireProofKindForValidationHeight(
        V2_SPEND_PATH_RECOVERY,
        ProofKind::DIRECT_MATRICT,
        consensus,
        validation_height);
    bundle.header.proof_envelope.membership_proof_kind = ProofComponentKind::MATRICT;
    bundle.header.proof_envelope.amount_proof_kind = ProofComponentKind::RANGE;
    bundle.header.proof_envelope.balance_proof_kind = ProofComponentKind::BALANCE;
    bundle.header.proof_envelope.settlement_binding_kind = GetWireSettlementBindingKindForValidationHeight(
        V2_SPEND_PATH_RECOVERY,
        SettlementBindingKind::NONE,
        consensus,
        validation_height);
    bundle.header.proof_envelope.extension_digest = uint256::ZERO;
    bundle.proof_shards.clear();
    bundle.header.proof_shard_count = 0;
    bundle.header.proof_shard_root = uint256::ZERO;
    bundle.output_chunks.clear();
    bundle.header.output_chunk_root = uint256::ZERO;
    bundle.header.output_chunk_count = 0;

    if (UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
        auto output_chunks = BuildDerivedGenericOutputChunks(bundle.payload);
        if (!output_chunks.has_value()) return false;
        bundle.output_chunks = std::move(*output_chunks);
        bundle.header.output_chunk_root = bundle.output_chunks.empty()
            ? uint256::ZERO
            : ComputeOutputChunkRoot(
                  Span<const sh::v2::OutputChunkDescriptor>{bundle.output_chunks.data(),
                                                            bundle.output_chunks.size()});
        bundle.header.output_chunk_count = bundle.output_chunks.size();
    }
    return true;
}

[[nodiscard]] std::optional<CMutableTransaction> BuildRecoveryTx(
    const std::vector<ShieldedNote>& legacy_notes,
    const sh::ShieldedMerkleTree& tree,
    uint64_t recovery_tree_position,
    CAmount recovery_fee,
    unsigned char seed_base,
    const Consensus::Params* consensus,
    int32_t validation_height,
    uint256& recovery_output_note_commitment,
    std::string& reject_reason)
{
    using namespace ::shielded::v2;

    if (legacy_notes.empty()) {
        reject_reason = "spend-path recovery fixture requires at least one legacy note";
        return std::nullopt;
    }
    if (recovery_tree_position >= legacy_notes.size()) {
        reject_reason = "spend-path recovery input tree position out of range";
        return std::nullopt;
    }
    const auto input_commitment = tree.CommitmentAt(recovery_tree_position);
    if (!input_commitment.has_value()) {
        reject_reason = "spend-path recovery input commitment missing from tree";
        return std::nullopt;
    }

    const ShieldedNote& input_note = legacy_notes[recovery_tree_position];
    if (input_note.value <= recovery_fee) {
        reject_reason = "spend-path recovery input note below fee";
        return std::nullopt;
    }

    const std::vector<unsigned char> spending_key(32, static_cast<unsigned char>(seed_base + 0x11));
    const std::vector<uint64_t> ring_positions{recovery_tree_position};
    const std::vector<std::vector<uint256>> ring_members{{*input_commitment}};
    const std::vector<size_t> real_indices{0};

    ShieldedNote output_note = MakeLegacyNote(input_note.value - recovery_fee,
                                              static_cast<unsigned char>(seed_base + 0x70));
    const auto output_recipient = BuildRecipientKeyPair(static_cast<unsigned char>(seed_base + 0x71));

    SpendDescription spend;
    if (!DeriveInputNullifierForNote(spend.nullifier,
                                     spending_key,
                                     input_note,
                                     *input_commitment)) {
        reject_reason = "failed to derive spend-path recovery nullifier";
        return std::nullopt;
    }
    spend.note_commitment = *input_commitment;
    spend.merkle_anchor = tree.Root();
    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    if (!input_account.has_value()) {
        reject_reason = "failed to derive spend-path recovery input account";
        return std::nullopt;
    }
    const auto account_registry_witness = ::test::shielded::MakeSingleLeafRegistryWitness(
        spend.note_commitment,
        *input_account);
    if (!account_registry_witness.has_value()) {
        reject_reason = "failed to build spend-path recovery registry witness";
        return std::nullopt;
    }
    spend.account_leaf_commitment = account_registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = account_registry_witness->second;
    spend.value_commitment = uint256{static_cast<unsigned char>(seed_base + 0x12)};

    auto output = BuildRecoveryOutput(output_note,
                                      output_recipient.pk,
                                      static_cast<unsigned char>(seed_base + 0x21),
                                      reject_reason);
    if (!reject_reason.empty()) return std::nullopt;

    SpendPathRecoveryPayload payload;
    payload.spend_anchor = tree.Root();
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = recovery_fee;

    TransactionBundle bundle;
    bundle.payload = payload;
    bundle.header.payload_digest = ComputeSpendPathRecoveryPayloadDigest(payload);
    if (!ApplyRecoveryWireEnvelope(bundle, consensus, validation_height)) {
        reject_reason = "failed to derive spend-path recovery output chunks";
        return std::nullopt;
    }

    CMutableTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.nLockTime = seed_base;
    tx.shielded_bundle.v2_bundle = bundle;

    std::vector<Nullifier> input_nullifiers{spend.nullifier};
    std::vector<uint256> output_note_commitments{output.note_commitment};

    const uint256 provisional_statement_digest =
        v2proof::ComputeSpendPathRecoveryStatementDigest(CTransaction{tx});
    MatRiCTProof provisional_proof;
    if (!CreateMatRiCTProof(provisional_proof,
                            {input_note},
                            {output_note},
                            Span<const uint256>{output_note_commitments.data(),
                                                output_note_commitments.size()},
                            input_nullifiers,
                            ring_members,
                            real_indices,
                            spending_key,
                            recovery_fee,
                            provisional_statement_digest,
                            {},
                            /*allow_singleton_ring=*/true)) {
        reject_reason = "failed to build provisional spend-path recovery proof";
        return std::nullopt;
    }

    spend.value_commitment = CommitmentHash(provisional_proof.input_commitments[0]);
    output.value_commitment = CommitmentHash(provisional_proof.output_commitments[0]);
    payload.spends = {spend};
    payload.outputs = {output};
    bundle.payload = payload;
    bundle.header.payload_digest = ComputeSpendPathRecoveryPayloadDigest(payload);
    if (!ApplyRecoveryWireEnvelope(bundle, consensus, validation_height)) {
        reject_reason = "failed to refresh spend-path recovery output chunks";
        return std::nullopt;
    }
    tx.shielded_bundle.v2_bundle = bundle;

    const uint256 statement_digest =
        v2proof::ComputeSpendPathRecoveryStatementDigest(CTransaction{tx});
    MatRiCTProof proof;
    if (!CreateMatRiCTProof(proof,
                            {input_note},
                            {output_note},
                            Span<const uint256>{output_note_commitments.data(),
                                                output_note_commitments.size()},
                            input_nullifiers,
                            ring_members,
                            real_indices,
                            spending_key,
                            recovery_fee,
                            statement_digest,
                            {},
                            /*allow_singleton_ring=*/true)) {
        reject_reason = "failed to build spend-path recovery proof";
        return std::nullopt;
    }

    v2proof::SpendPathRecoveryWitness witness;
    v2proof::SpendPathRecoverySpendWitness spend_witness;
    spend_witness.ring_positions = ring_positions;
    witness.spends = {spend_witness};
    witness.native_proof = proof;

    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    bundle.header.proof_envelope.statement_digest = statement_digest;
    bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
    bundle.payload = payload;
    bundle.header.payload_digest = ComputeSpendPathRecoveryPayloadDigest(payload);
    if (!ApplyRecoveryWireEnvelope(bundle, consensus, validation_height)) {
        reject_reason = "failed to finalize spend-path recovery output chunks";
        return std::nullopt;
    }
    bundle.header.proof_envelope.statement_digest = statement_digest;
    if (!bundle.IsValid()) {
        reject_reason = "invalid spend-path recovery bundle";
        return std::nullopt;
    }
    tx.shielded_bundle.v2_bundle = bundle;
    recovery_output_note_commitment = output.note_commitment;
    return tx;
}

} // namespace

std::optional<SpendPathRecoveryFixtureBuildResult> BuildSpendPathRecoveryFixture(
    const SpendPathRecoveryFixtureBuildInput& input,
    std::string& reject_reason)
{
    SpendPathRecoveryFixtureBuildResult result;
    if (input.legacy_funding_inputs.empty()) {
        reject_reason = "spend-path recovery fixture requires at least one funding input";
        return std::nullopt;
    }
    if (input.validation_height <= 0) {
        reject_reason = "spend-path recovery fixture requires a positive validation height";
        return std::nullopt;
    }
    if (input.matrict_disable_height <= 0) {
        reject_reason = "spend-path recovery fixture requires a positive MatRiCT disable height";
        return std::nullopt;
    }
    if (input.validation_height < input.matrict_disable_height) {
        reject_reason =
            "state-aware spend-path recovery fixture requires post-disable validation heights";
        return std::nullopt;
    }
    if (!MoneyRange(input.legacy_shield_fee) || input.legacy_shield_fee <= 0 ||
        !MoneyRange(input.recovery_fee) || input.recovery_fee <= 0) {
        reject_reason = "invalid spend-path recovery fee configuration";
        return std::nullopt;
    }
    if (input.recovery_recipient_pk_hash.has_value() !=
        input.recovery_recipient_kem_public_key.has_value()) {
        reject_reason =
            "recovery recipient overrides require both pk hash and KEM public key";
        return std::nullopt;
    }

    sh::ShieldedMerkleTree tree;
    result.legacy_anchor = tree.Root();
    if (result.legacy_anchor.IsNull()) {
        reject_reason = "empty shielded tree root is unavailable";
        return std::nullopt;
    }

    std::vector<ShieldedNote> ring_notes;
    ring_notes.reserve(input.legacy_funding_inputs.size());
    result.legacy_txs.reserve(input.legacy_funding_inputs.size());
    result.legacy_note_commitments.reserve(input.legacy_funding_inputs.size());

    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        const auto& funding = input.legacy_funding_inputs[i];
        if (!MoneyRange(funding.funding_value) || funding.funding_value <= input.legacy_shield_fee) {
            reject_reason = "legacy funding amount does not cover fee";
            return std::nullopt;
        }
        const auto note_value = funding.funding_value - input.legacy_shield_fee;
        const bool use_overridden_recovery_recipient =
            i == 0 &&
            input.recovery_recipient_pk_hash.has_value() &&
            input.recovery_recipient_kem_public_key.has_value();
        ShieldedNote note = use_overridden_recovery_recipient
            ? MakeLegacyNote(note_value,
                             *input.recovery_recipient_pk_hash,
                             static_cast<unsigned char>(input.seed_base + i * 3))
            : MakeLegacyNote(note_value,
                             static_cast<unsigned char>(input.seed_base + i * 3));
        const mlkem::PublicKey recipient_pk = use_overridden_recovery_recipient
            ? *input.recovery_recipient_kem_public_key
            : BuildRecipientKeyPair(static_cast<unsigned char>(input.seed_base + 0x40 + i)).pk;
        const uint256 current_legacy_anchor = tree.Root();
        auto tx = BuildUnsignedLegacyShieldOnlyTx(funding,
                                                  current_legacy_anchor,
                                                  note,
                                                  recipient_pk,
                                                  static_cast<unsigned char>(input.seed_base + i),
                                                  input.legacy_shield_fee,
                                                  reject_reason);
        if (!tx.has_value()) {
            return std::nullopt;
        }
        result.legacy_note_commitments.push_back(note.GetCommitment());
        tree.Append(note.GetCommitment());
        ring_notes.push_back(std::move(note));
        result.legacy_txs.push_back(std::move(*tx));
    }

    result.recovery_anchor = tree.Root();
    constexpr uint64_t recovery_tree_position = 0;
    result.recovery_input_note_commitment = result.legacy_note_commitments[recovery_tree_position];
    Consensus::Params wire_consensus;
    wire_consensus.nShieldedMatRiCTDisableHeight = input.matrict_disable_height;

    auto recovery_tx = BuildRecoveryTx(ring_notes,
                                       tree,
                                       recovery_tree_position,
                                       input.recovery_fee,
                                       static_cast<unsigned char>(input.seed_base + 0x80),
                                       &wire_consensus,
                                       input.validation_height,
                                       result.recovery_output_note_commitment,
                                       reject_reason);
    if (!recovery_tx.has_value()) {
        return std::nullopt;
    }
    result.recovery_tx = std::move(*recovery_tx);
    return result;
}

} // namespace btx::test::shielded
