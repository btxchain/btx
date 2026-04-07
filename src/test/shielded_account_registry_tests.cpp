// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hash.h>
#include <shielded/account_registry.h>
#include <shielded/bundle.h>
#include <shielded/v2_bundle.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {

using namespace shielded::registry;

shielded::v2::EncryptedNotePayload MakeEncryptedNotePayload(shielded::v2::ScanDomain scan_domain,
                                                            unsigned char seed)
{
    shielded::v2::EncryptedNotePayload payload;
    payload.scan_domain = scan_domain;
    payload.scan_hint = {seed, static_cast<uint8_t>(seed + 1), static_cast<uint8_t>(seed + 2), static_cast<uint8_t>(seed + 3)};
    payload.ciphertext = {
        static_cast<uint8_t>(seed + 4),
        static_cast<uint8_t>(seed + 5),
        static_cast<uint8_t>(seed + 6),
        static_cast<uint8_t>(seed + 7),
    };
    payload.ephemeral_key = shielded::v2::ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{payload.ciphertext.data(), payload.ciphertext.size()});
    return payload;
}

shielded::v2::OutputDescription MakeOutput(shielded::v2::NoteClass note_class,
                                           shielded::v2::ScanDomain scan_domain,
                                           unsigned char seed)
{
    shielded::v2::OutputDescription output;
    output.note_class = note_class;
    output.smile_account = test::shielded::MakeDeterministicCompactPublicAccount(seed);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.encrypted_note = MakeEncryptedNotePayload(scan_domain, static_cast<unsigned char>(seed + 11));
    return output;
}

shielded::v2::OutputDescription MakeDirectOutput(unsigned char seed)
{
    auto output = MakeOutput(shielded::v2::NoteClass::USER, shielded::v2::ScanDomain::USER, seed);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid direct output fixture");
    }
    return output;
}

shielded::v2::OutputDescription MakeIngressReserveOutput(unsigned char seed,
                                                         const uint256& settlement_binding_digest,
                                                         uint32_t output_index)
{
    auto output = MakeOutput(shielded::v2::NoteClass::RESERVE, shielded::v2::ScanDomain::RESERVE, seed);
    output.value_commitment = shielded::v2::ComputeV2IngressPlaceholderReserveValueCommitment(
        settlement_binding_digest,
        output_index,
        output.note_commitment);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid ingress output fixture");
    }
    return output;
}

shielded::v2::OutputDescription MakeEgressOutput(unsigned char seed,
                                                 const uint256& output_binding_digest,
                                                 uint32_t output_index)
{
    auto output = MakeOutput(shielded::v2::NoteClass::USER, shielded::v2::ScanDomain::BATCH, seed);
    output.value_commitment = shielded::v2::ComputeV2EgressOutputValueCommitment(output_binding_digest,
                                                                                  output_index,
                                                                                  output.note_commitment);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid egress output fixture");
    }
    return output;
}

shielded::v2::OutputDescription MakeRebalanceOutput(unsigned char seed, uint32_t output_index)
{
    auto output = MakeOutput(shielded::v2::NoteClass::RESERVE, shielded::v2::ScanDomain::RESERVE, seed);
    output.value_commitment = shielded::v2::ComputeV2RebalanceOutputValueCommitment(output_index,
                                                                                     output.note_commitment);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid rebalance output fixture");
    }
    return output;
}

uint256 HashCommitments(Span<const uint256> commitments)
{
    HashWriter hw;
    std::vector<uint256> commitment_vec{commitments.begin(), commitments.end()};
    hw << commitment_vec;
    return hw.GetSHA256();
}

struct RegistryPayloadStoreGuard
{
    explicit RegistryPayloadStoreGuard(const fs::path& db_path)
    {
        ShieldedAccountRegistryState::ResetPayloadStore();
        BOOST_REQUIRE(ShieldedAccountRegistryState::ConfigurePayloadStore(db_path,
                                                                          1 << 20,
                                                                          /*memory_only=*/false,
                                                                          /*wipe_data=*/true));
    }

    ~RegistryPayloadStoreGuard() { ShieldedAccountRegistryState::ResetPayloadStore(); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_account_registry_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(account_leaf_commitments_are_deterministic_and_domain_separated)
{
    const uint256 ingress_binding{0x41};
    const uint256 egress_binding{0x42};
    const uint256 egress_output_binding{0x43};
    const uint256 rebalance_binding{0x44};

    const auto direct_output = MakeDirectOutput(0x10);
    const auto ingress_output = MakeIngressReserveOutput(0x10, ingress_binding, 0);
    const auto egress_output = MakeEgressOutput(0x10, egress_output_binding, 0);
    const auto rebalance_output = MakeRebalanceOutput(0x10, 0);

    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    const auto ingress_leaf = BuildIngressAccountLeaf(ingress_output, ingress_binding);
    const auto egress_leaf = BuildEgressAccountLeaf(egress_output, egress_binding, egress_output_binding);
    const auto rebalance_leaf = BuildRebalanceAccountLeaf(rebalance_output, rebalance_binding);

    BOOST_REQUIRE(direct_leaf.has_value());
    BOOST_REQUIRE(ingress_leaf.has_value());
    BOOST_REQUIRE(egress_leaf.has_value());
    BOOST_REQUIRE(rebalance_leaf.has_value());

    BOOST_CHECK(direct_leaf->IsValid());
    BOOST_CHECK(ingress_leaf->IsValid());
    BOOST_CHECK(egress_leaf->IsValid());
    BOOST_CHECK(rebalance_leaf->IsValid());

    BOOST_CHECK(!direct_leaf->bridge_tag.has_value());
    BOOST_CHECK(ingress_leaf->bridge_tag.has_value());
    BOOST_CHECK(egress_leaf->bridge_tag.has_value());
    BOOST_CHECK(rebalance_leaf->bridge_tag.has_value());

    const uint256 direct_commitment = ComputeShieldedAccountLeafCommitment(*direct_leaf);
    const uint256 ingress_commitment = ComputeShieldedAccountLeafCommitment(*ingress_leaf);
    const uint256 egress_commitment = ComputeShieldedAccountLeafCommitment(*egress_leaf);
    const uint256 rebalance_commitment = ComputeShieldedAccountLeafCommitment(*rebalance_leaf);

    BOOST_CHECK(!direct_commitment.IsNull());
    BOOST_CHECK(!ingress_commitment.IsNull());
    BOOST_CHECK(!egress_commitment.IsNull());
    BOOST_CHECK(!rebalance_commitment.IsNull());

    BOOST_CHECK_EQUAL(direct_commitment, ComputeShieldedAccountLeafCommitment(*direct_leaf));
    BOOST_CHECK(direct_commitment != ingress_commitment);
    BOOST_CHECK(direct_commitment != egress_commitment);
    BOOST_CHECK(direct_commitment != rebalance_commitment);
    BOOST_CHECK(ingress_commitment != egress_commitment);
    BOOST_CHECK(ingress_commitment != rebalance_commitment);
    BOOST_CHECK(egress_commitment != rebalance_commitment);
}

BOOST_AUTO_TEST_CASE(account_leaf_commitments_do_not_correlate_same_recipient_across_notes)
{
    ShieldedNote first_note = test::shielded::MakeDeterministicSmileNote(0x71, 9 * COIN);
    ShieldedNote second_note = test::shielded::MakeDeterministicSmileNote(0x72, 9 * COIN);
    second_note.recipient_pk_hash = first_note.recipient_pk_hash;

    const auto first_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        first_note);
    const auto second_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        second_note);
    BOOST_REQUIRE(first_account.has_value());
    BOOST_REQUIRE(second_account.has_value());

    const uint256 first_note_commitment = smile2::ComputeCompactPublicAccountHash(*first_account);
    const uint256 second_note_commitment = smile2::ComputeCompactPublicAccountHash(*second_account);
    BOOST_CHECK(first_note_commitment != second_note_commitment);

    const uint256 first_spend_tag = ComputeSpendTagCommitment(*first_account, first_note_commitment);
    const uint256 second_spend_tag = ComputeSpendTagCommitment(*second_account, second_note_commitment);
    BOOST_CHECK(first_spend_tag != second_spend_tag);

    const auto first_leaf = BuildShieldedAccountLeaf(*first_account,
                                                     first_note_commitment,
                                                     AccountDomain::DIRECT_SEND);
    const auto second_leaf = BuildShieldedAccountLeaf(*second_account,
                                                      second_note_commitment,
                                                      AccountDomain::DIRECT_SEND);
    BOOST_REQUIRE(first_leaf.has_value());
    BOOST_REQUIRE(second_leaf.has_value());
    BOOST_CHECK(ComputeShieldedAccountLeafCommitment(*first_leaf) !=
                ComputeShieldedAccountLeafCommitment(*second_leaf));
}

BOOST_AUTO_TEST_CASE(bridge_tag_upgrade_changes_commitment_and_candidate_set)
{
    const ShieldedNote note = test::shielded::MakeDeterministicSmileNote(0x51, 7 * COIN);
    const auto account =
        smile2::wallet::BuildCompactPublicAccountFromNote(smile2::wallet::SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(account.has_value());
    const uint256 note_commitment = smile2::ComputeCompactPublicAccountHash(*account);
    const auto ingress_hint = MakeIngressAccountLeafHint(uint256{0x91});
    BOOST_REQUIRE(ingress_hint.has_value());

    const auto legacy_commitment =
        ComputeAccountLeafCommitmentFromNote(note, note_commitment, *ingress_hint, false);
    const auto upgraded_commitment =
        ComputeAccountLeafCommitmentFromNote(note, note_commitment, *ingress_hint, true);
    const auto candidates =
        CollectAccountLeafCommitmentCandidatesFromNote(note, note_commitment, *ingress_hint);

    BOOST_REQUIRE(legacy_commitment.has_value());
    BOOST_REQUIRE(upgraded_commitment.has_value());
    BOOST_CHECK(*legacy_commitment != *upgraded_commitment);
    BOOST_REQUIRE_EQUAL(candidates.size(), 2U);
    BOOST_CHECK(std::find(candidates.begin(), candidates.end(), *legacy_commitment) != candidates.end());
    BOOST_CHECK(std::find(candidates.begin(), candidates.end(), *upgraded_commitment) != candidates.end());
}

BOOST_AUTO_TEST_CASE(minimal_direct_output_roundtrips_and_is_smaller_than_current_output)
{
    const auto direct_output = MakeDirectOutput(0x21);
    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    const auto minimal_output = BuildDirectSendMinimalOutput(direct_output);

    BOOST_REQUIRE(direct_leaf.has_value());
    BOOST_REQUIRE(minimal_output.has_value());
    BOOST_REQUIRE(MinimalOutputRecordMatchesOutput(*minimal_output, direct_output, *direct_leaf));

    DataStream current_stream;
    direct_output.SerializeDirectSend(current_stream,
                                      shielded::v2::NoteClass::USER,
                                      shielded::v2::ScanDomain::USER);
    const auto minimal_bytes = SerializeMinimalOutputRecord(*minimal_output,
                                                            AccountDomain::DIRECT_SEND,
                                                            shielded::v2::ScanDomain::USER);

    BOOST_CHECK_LT(minimal_bytes.size(), current_stream.size());

    const auto roundtrip = DeserializeMinimalOutputRecord(
        Span<const uint8_t>{minimal_bytes.data(), minimal_bytes.size()},
        AccountDomain::DIRECT_SEND,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(roundtrip.has_value());
    BOOST_CHECK(roundtrip->IsValid());
    BOOST_CHECK_EQUAL(roundtrip->note_commitment, minimal_output->note_commitment);
    BOOST_CHECK_EQUAL(roundtrip->account_leaf_commitment, minimal_output->account_leaf_commitment);
    BOOST_CHECK(roundtrip->encrypted_note.scan_hint == minimal_output->encrypted_note.scan_hint);
    BOOST_CHECK(roundtrip->encrypted_note.ciphertext == minimal_output->encrypted_note.ciphertext);
    BOOST_CHECK_EQUAL(roundtrip->encrypted_note.ephemeral_key,
                      minimal_output->encrypted_note.ephemeral_key);
}

BOOST_AUTO_TEST_CASE(registry_state_proofs_snapshot_and_state_commitments_work)
{
    const uint256 ingress_binding{0x61};
    const uint256 egress_binding{0x62};
    const uint256 egress_output_binding{0x63};
    const uint256 rebalance_binding{0x64};

    const auto direct_output = MakeDirectOutput(0x31);
    const auto ingress_output = MakeIngressReserveOutput(0x32, ingress_binding, 0);
    const auto egress_output = MakeEgressOutput(0x33, egress_output_binding, 0);
    const auto rebalance_output = MakeRebalanceOutput(0x34, 0);

    const auto direct_minimal = BuildDirectSendMinimalOutput(direct_output);
    const auto ingress_minimal = BuildIngressMinimalOutput(ingress_output, ingress_binding);
    const auto egress_minimal = BuildEgressMinimalOutput(egress_output, egress_binding, egress_output_binding);
    const auto rebalance_minimal = BuildRebalanceMinimalOutput(rebalance_output, rebalance_binding);

    BOOST_REQUIRE(direct_minimal.has_value());
    BOOST_REQUIRE(ingress_minimal.has_value());
    BOOST_REQUIRE(egress_minimal.has_value());
    BOOST_REQUIRE(rebalance_minimal.has_value());
    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    const auto ingress_leaf = BuildIngressAccountLeaf(ingress_output, ingress_binding);
    const auto egress_leaf = BuildEgressAccountLeaf(egress_output, egress_binding, egress_output_binding);
    const auto rebalance_leaf = BuildRebalanceAccountLeaf(rebalance_output, rebalance_binding);

    BOOST_REQUIRE(direct_leaf.has_value());
    BOOST_REQUIRE(ingress_leaf.has_value());
    BOOST_REQUIRE(egress_leaf.has_value());
    BOOST_REQUIRE(rebalance_leaf.has_value());

    ShieldedAccountRegistryState registry_state;
    std::vector<uint64_t> inserted_indices;
    const std::vector<ShieldedAccountLeaf> leaves{
        *direct_leaf,
        *ingress_leaf,
        *egress_leaf,
        *rebalance_leaf,
    };
    BOOST_REQUIRE(registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()},
                                        &inserted_indices));
    BOOST_REQUIRE_EQUAL(inserted_indices.size(), leaves.size());
    BOOST_CHECK_EQUAL(registry_state.Size(), 4U);

    const uint256 root = registry_state.Root();
    BOOST_CHECK(!root.IsNull());

    const auto proof = registry_state.BuildProof(inserted_indices[2]);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(VerifyShieldedAccountRegistryProof(*proof, root));
    const auto spend_witness = registry_state.BuildSpendWitness(inserted_indices[2]);
    BOOST_REQUIRE(spend_witness.has_value());
    BOOST_CHECK(VerifyShieldedAccountRegistrySpendWitness(*spend_witness,
                                                          registry_state,
                                                          root));
    const auto proof_leaf = DeserializeShieldedAccountLeafPayload(
        Span<const uint8_t>{proof->entry.account_leaf_payload.data(), proof->entry.account_leaf_payload.size()});
    BOOST_REQUIRE(proof_leaf.has_value());
    const auto proof_account = BuildCompactPublicAccountFromAccountLeaf(*proof_leaf);
    BOOST_REQUIRE(proof_account.has_value());
    BOOST_CHECK_EQUAL(ComputeShieldedAccountLeafCommitment(*proof_leaf),
                      proof->entry.account_leaf_commitment);
    BOOST_CHECK(proof_account->public_key == egress_output.smile_account->public_key);
    BOOST_CHECK(proof_account->public_coin.t0 == egress_output.smile_account->public_coin.t0);
    BOOST_CHECK(proof_account->public_coin.t_msg == egress_output.smile_account->public_coin.t_msg);

    const std::vector<uint256> note_commitments{
        direct_minimal->note_commitment,
        ingress_minimal->note_commitment,
        egress_minimal->note_commitment,
        rebalance_minimal->note_commitment,
    };
    ShieldedStateCommitment commitment_before_spend;
    commitment_before_spend.note_commitment_root = HashCommitments(
        Span<const uint256>{note_commitments.data(), note_commitments.size()});
    commitment_before_spend.account_registry_root = root;
    const std::vector<uint256> nullifiers{uint256{0x91}, uint256{0x92}};
    commitment_before_spend.nullifier_root = ComputeNullifierSetCommitment(
        Span<const uint256>{nullifiers.data(), nullifiers.size()});
    commitment_before_spend.bridge_settlement_root = uint256{0x93};
    BOOST_CHECK(commitment_before_spend.IsValid());
    BOOST_CHECK(!ComputeShieldedStateCommitmentHash(commitment_before_spend).IsNull());
    BOOST_CHECK(VerifyShieldedStateInclusion(commitment_before_spend, *proof));

    DataStream spend_witness_stream;
    spend_witness_stream << *spend_witness;
    BOOST_CHECK_GT(spend_witness_stream.size(), 0U);
    shielded::registry::ShieldedAccountRegistrySpendWitness restored_spend_witness;
    spend_witness_stream >> restored_spend_witness;
    BOOST_CHECK(restored_spend_witness.IsValid());
    BOOST_CHECK(VerifyShieldedAccountRegistrySpendWitness(restored_spend_witness,
                                                          registry_state,
                                                          root));

    const auto snapshot = registry_state.ExportSnapshot();
    BOOST_CHECK(snapshot.IsValid());
    DataStream snapshot_stream;
    snapshot_stream << snapshot;
    BOOST_CHECK_GT(snapshot_stream.size(), 0U);

    ShieldedAccountRegistrySnapshot restored_snapshot;
    snapshot_stream >> restored_snapshot;
    auto restored_state = ShieldedAccountRegistryState::Restore(restored_snapshot);
    BOOST_REQUIRE(restored_state.has_value());
    BOOST_CHECK_EQUAL(restored_state->Root(), root);
    BOOST_REQUIRE(restored_state->Truncate(2));
    BOOST_CHECK_EQUAL(restored_state->Size(), 2U);
    BOOST_CHECK(restored_state->Root() != root);
}

BOOST_AUTO_TEST_CASE(tampered_proofs_and_missing_smile_accounts_are_rejected)
{
    const auto direct_output = MakeDirectOutput(0x41);
    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    const auto direct_minimal = BuildDirectSendMinimalOutput(direct_output);

    BOOST_REQUIRE(direct_leaf.has_value());
    BOOST_REQUIRE(direct_minimal.has_value());

    ShieldedAccountRegistryState registry_state;
    const std::vector<ShieldedAccountLeaf> leaves{*direct_leaf};
    BOOST_REQUIRE(registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    const uint256 root = registry_state.Root();
    const auto proof = registry_state.BuildProof(0);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(VerifyShieldedAccountRegistryProof(*proof, root));
    const auto spend_witness = registry_state.BuildSpendWitness(0);
    BOOST_REQUIRE(spend_witness.has_value());
    BOOST_CHECK(VerifyShieldedAccountRegistrySpendWitness(*spend_witness, registry_state, root));

    auto tampered_sibling = *proof;
    tampered_sibling.sibling_path.push_back(uint256{0xa1});
    BOOST_CHECK(!VerifyShieldedAccountRegistryProof(tampered_sibling, root));
    auto tampered_spend_sibling = *spend_witness;
    tampered_spend_sibling.sibling_path.push_back(uint256{0xa1});
    BOOST_CHECK(!VerifyShieldedAccountRegistrySpendWitness(tampered_spend_sibling, registry_state, root));

    auto tampered_entry = *proof;
    tampered_entry.entry.account_leaf_commitment = uint256{0xa2};
    BOOST_CHECK(!VerifyShieldedAccountRegistryProof(tampered_entry, root));
    auto tampered_spend_entry = *spend_witness;
    tampered_spend_entry.account_leaf_commitment = uint256{0xa2};
    BOOST_CHECK(!VerifyShieldedAccountRegistrySpendWitness(tampered_spend_entry, registry_state, root));

    auto tampered_payload = *proof;
    tampered_payload.entry.account_leaf_payload.back() ^= 0x01;
    BOOST_CHECK(!VerifyShieldedAccountRegistryProof(tampered_payload, root));

    ShieldedStateCommitment wrong_commitment;
    wrong_commitment.note_commitment_root = uint256{0xb1};
    wrong_commitment.account_registry_root = uint256{0xb2};
    const std::vector<uint256> empty_nullifiers;
    wrong_commitment.nullifier_root = ComputeNullifierSetCommitment(
        Span<const uint256>{empty_nullifiers.data(), empty_nullifiers.size()});
    wrong_commitment.bridge_settlement_root = uint256{0xb3};
    BOOST_CHECK(wrong_commitment.IsValid());
    BOOST_CHECK(!VerifyShieldedStateInclusion(wrong_commitment, *proof));

    shielded::v2::OutputDescription invalid_output = direct_output;
    invalid_output.smile_account.reset();
    BOOST_CHECK(!BuildDirectSendAccountLeaf(invalid_output).has_value());
    BOOST_CHECK(!BuildDirectSendMinimalOutput(invalid_output).has_value());
}

BOOST_AUTO_TEST_CASE(account_registry_rejects_duplicate_leaf_commitments)
{
    const auto direct_output = MakeDirectOutput(0x51);
    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    BOOST_REQUIRE(direct_leaf.has_value());

    ShieldedAccountRegistryState registry_state =
        ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const std::vector<ShieldedAccountLeaf> initial_batch{*direct_leaf};
    BOOST_REQUIRE(registry_state.Append(
        Span<const ShieldedAccountLeaf>{initial_batch.data(), initial_batch.size()}));

    const std::vector<ShieldedAccountLeaf> duplicate_existing{*direct_leaf};
    BOOST_CHECK(!registry_state.Append(
        Span<const ShieldedAccountLeaf>{duplicate_existing.data(), duplicate_existing.size()}));

    ShieldedAccountRegistryState empty_registry;
    const std::vector<ShieldedAccountLeaf> duplicate_batch{*direct_leaf, *direct_leaf};
    BOOST_CHECK(!empty_registry.Append(
        Span<const ShieldedAccountLeaf>{duplicate_batch.data(), duplicate_batch.size()}));
}

BOOST_AUTO_TEST_CASE(account_registry_rejects_spent_and_duplicate_snapshot_entries)
{
    const auto first_output = MakeDirectOutput(0x61);
    const auto first_leaf = BuildDirectSendAccountLeaf(first_output);
    BOOST_REQUIRE(first_leaf.has_value());

    ShieldedAccountRegistryState registry_state;
    const std::vector<ShieldedAccountLeaf> initial_batch{*first_leaf};
    BOOST_REQUIRE(registry_state.Append(
        Span<const ShieldedAccountLeaf>{initial_batch.data(), initial_batch.size()}));

    auto spent_snapshot = registry_state.ExportSnapshot();
    BOOST_REQUIRE_EQUAL(spent_snapshot.entries.size(), 1U);
    spent_snapshot.entries[0].spent = true;
    BOOST_CHECK(!spent_snapshot.IsValid());
    BOOST_CHECK(!ShieldedAccountRegistryState::Restore(spent_snapshot).has_value());

    const auto second_output = MakeDirectOutput(0x62);
    const auto second_leaf = BuildDirectSendAccountLeaf(second_output);
    BOOST_REQUIRE(second_leaf.has_value());
    const std::vector<ShieldedAccountLeaf> second_batch{*second_leaf};
    BOOST_REQUIRE(registry_state.Append(
        Span<const ShieldedAccountLeaf>{second_batch.data(), second_batch.size()}));

    auto duplicate_snapshot = registry_state.ExportSnapshot();
    BOOST_REQUIRE_EQUAL(duplicate_snapshot.entries.size(), 2U);
    duplicate_snapshot.entries[1].account_leaf_commitment =
        duplicate_snapshot.entries[0].account_leaf_commitment;
    duplicate_snapshot.entries[1].account_leaf_payload =
        duplicate_snapshot.entries[0].account_leaf_payload;
    BOOST_CHECK(!duplicate_snapshot.IsValid());
    BOOST_CHECK(!ShieldedAccountRegistryState::Restore(duplicate_snapshot).has_value());
}

BOOST_AUTO_TEST_CASE(registry_snapshot_rebuilds_public_account_state)
{
    const auto direct_output = MakeDirectOutput(0x45);
    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    BOOST_REQUIRE(direct_leaf.has_value());

    ShieldedAccountRegistryState registry_state;
    const std::vector<ShieldedAccountLeaf> leaves{*direct_leaf};
    BOOST_REQUIRE(registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    BOOST_REQUIRE(BuildRegistryAccountState(registry_state, public_accounts, account_leaf_commitments));
    BOOST_REQUIRE_EQUAL(public_accounts.size(), 1U);
    BOOST_REQUIRE_EQUAL(account_leaf_commitments.size(), 1U);
    BOOST_CHECK(public_accounts.at(direct_output.note_commitment).public_key ==
                direct_output.smile_account->public_key);
    BOOST_CHECK(public_accounts.at(direct_output.note_commitment).public_coin.t0 ==
                direct_output.smile_account->public_coin.t0);
    BOOST_CHECK(public_accounts.at(direct_output.note_commitment).public_coin.t_msg ==
                direct_output.smile_account->public_coin.t_msg);
    BOOST_CHECK_EQUAL(account_leaf_commitments.at(direct_output.note_commitment),
                      ComputeShieldedAccountLeafCommitment(*direct_leaf));
}

BOOST_AUTO_TEST_CASE(registry_externalized_payload_store_and_persisted_snapshot_roundtrip)
{
    RegistryPayloadStoreGuard payload_store_guard(m_path_root / "registry_payload_store");

    const auto first_output = MakeDirectOutput(0x81);
    const auto second_output = MakeDirectOutput(0x82);
    const auto first_leaf = BuildDirectSendAccountLeaf(first_output);
    const auto second_leaf = BuildDirectSendAccountLeaf(second_output);
    BOOST_REQUIRE(first_leaf.has_value());
    BOOST_REQUIRE(second_leaf.has_value());

    ShieldedAccountRegistryState registry_state =
        ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const std::vector<ShieldedAccountLeaf> leaves{*first_leaf, *second_leaf};
    BOOST_REQUIRE(registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    const uint256 root = registry_state.Root();
    BOOST_CHECK(!root.IsNull());

    const auto full_snapshot = registry_state.ExportSnapshot();
    BOOST_REQUIRE(full_snapshot.IsValid());
    const auto persisted_snapshot = registry_state.ExportPersistedSnapshot();
    BOOST_REQUIRE(persisted_snapshot.IsValid());

    DataStream full_stream;
    full_stream << full_snapshot;
    DataStream persisted_stream;
    persisted_stream << persisted_snapshot;
    BOOST_CHECK_LT(persisted_stream.size(), full_stream.size());

    auto restored_from_persisted = ShieldedAccountRegistryState::RestorePersisted(persisted_snapshot);
    BOOST_REQUIRE(restored_from_persisted.has_value());
    BOOST_CHECK_EQUAL(restored_from_persisted->Size(), registry_state.Size());
    BOOST_CHECK_EQUAL(restored_from_persisted->Root(), root);
    BOOST_CHECK(registry_state.CanMaterializeAllEntries());
    BOOST_CHECK(restored_from_persisted->CanMaterializeAllEntries());
    BOOST_REQUIRE(registry_state.MaterializeEntry(0).has_value());
    BOOST_REQUIRE(registry_state.MaterializeEntry(1).has_value());
    BOOST_REQUIRE(restored_from_persisted->MaterializeEntry(0).has_value());
    BOOST_REQUIRE(restored_from_persisted->MaterializeEntry(1).has_value());

    std::map<uint256, smile2::CompactPublicAccount> original_public_accounts;
    std::map<uint256, uint256> original_account_leaf_commitments;
    BOOST_REQUIRE(BuildRegistryAccountState(registry_state,
                                            original_public_accounts,
                                            original_account_leaf_commitments));
    BOOST_CHECK_EQUAL(original_public_accounts.size(), 2U);
    BOOST_CHECK_EQUAL(original_account_leaf_commitments.size(), 2U);

    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    BOOST_REQUIRE(BuildRegistryAccountState(*restored_from_persisted,
                                            public_accounts,
                                            account_leaf_commitments));
    BOOST_CHECK_EQUAL(public_accounts.size(), 2U);
    BOOST_CHECK_EQUAL(account_leaf_commitments.size(), 2U);
    for (const auto& [note_commitment, account] : original_public_accounts) {
        BOOST_REQUIRE(public_accounts.contains(note_commitment));
        BOOST_CHECK(public_accounts.at(note_commitment).public_key == account.public_key);
        BOOST_CHECK(public_accounts.at(note_commitment).public_coin.t0 == account.public_coin.t0);
        BOOST_CHECK(public_accounts.at(note_commitment).public_coin.t_msg == account.public_coin.t_msg);
    }
    BOOST_CHECK(account_leaf_commitments == original_account_leaf_commitments);

    const auto spend_witness = restored_from_persisted->BuildSpendWitnessByCommitment(
        ComputeShieldedAccountLeafCommitment(*second_leaf));
    BOOST_REQUIRE(spend_witness.has_value());
    BOOST_CHECK(VerifyShieldedAccountRegistrySpendWitness(*spend_witness,
                                                          *restored_from_persisted,
                                                          root));
}

BOOST_AUTO_TEST_CASE(registry_persisted_snapshot_requires_payload_store_and_full_restore_rehydrates_it)
{
    const auto direct_output = MakeDirectOutput(0x83);
    const auto direct_leaf = BuildDirectSendAccountLeaf(direct_output);
    BOOST_REQUIRE(direct_leaf.has_value());

    const auto db_path = m_path_root / "registry_payload_store_rehydrate";
    ShieldedAccountRegistryState::ResetPayloadStore();
    BOOST_REQUIRE(ShieldedAccountRegistryState::ConfigurePayloadStore(db_path,
                                                                      1 << 20,
                                                                      /*memory_only=*/false,
                                                                      /*wipe_data=*/true));
    shielded::registry::ShieldedAccountRegistryPersistedSnapshot persisted_snapshot;
    shielded::registry::ShieldedAccountRegistrySnapshot full_snapshot;
    {
        ShieldedAccountRegistryState registry_state =
            ShieldedAccountRegistryState::WithConfiguredPayloadStore();
        const std::vector<ShieldedAccountLeaf> leaves{*direct_leaf};
        BOOST_REQUIRE(
            registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

        persisted_snapshot = registry_state.ExportPersistedSnapshot();
        BOOST_REQUIRE(persisted_snapshot.IsValid());
        full_snapshot = registry_state.ExportSnapshot();
        BOOST_REQUIRE(full_snapshot.IsValid());
    }

    ShieldedAccountRegistryState::ResetPayloadStore();
    BOOST_CHECK(!ShieldedAccountRegistryState::RestorePersisted(persisted_snapshot).has_value());
    BOOST_REQUIRE(ShieldedAccountRegistryState::ConfigurePayloadStore(db_path,
                                                                      1 << 20,
                                                                      /*memory_only=*/false,
                                                                      /*wipe_data=*/true));
    auto restored_full = ShieldedAccountRegistryState::Restore(full_snapshot);
    BOOST_REQUIRE(restored_full.has_value());

    auto restored_persisted = ShieldedAccountRegistryState::RestorePersisted(persisted_snapshot);
    BOOST_REQUIRE(restored_persisted.has_value());
    BOOST_CHECK_EQUAL(restored_persisted->Root(), restored_full->Root());
    ShieldedAccountRegistryState::ResetPayloadStore();
}

BOOST_AUTO_TEST_CASE(registry_truncate_prunes_externalized_payloads)
{
    RegistryPayloadStoreGuard payload_store_guard(m_path_root / "registry_payload_store_truncate_prune");

    const auto first_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x91));
    const auto second_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x92));
    const auto third_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x93));
    BOOST_REQUIRE(first_leaf.has_value());
    BOOST_REQUIRE(second_leaf.has_value());
    BOOST_REQUIRE(third_leaf.has_value());

    ShieldedAccountRegistryState registry_state =
        ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const std::vector<ShieldedAccountLeaf> leaves{*first_leaf, *second_leaf, *third_leaf};
    BOOST_REQUIRE(
        registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    const auto full_persisted = registry_state.ExportPersistedSnapshot();
    BOOST_REQUIRE(full_persisted.IsValid());
    BOOST_REQUIRE_EQUAL(full_persisted.entries.size(), 3U);

    BOOST_REQUIRE(registry_state.Truncate(2));
    BOOST_CHECK_EQUAL(registry_state.Size(), 2U);
    BOOST_REQUIRE(!registry_state.MaterializeEntry(2).has_value());

    const auto truncated_persisted = registry_state.ExportPersistedSnapshot();
    BOOST_REQUIRE(truncated_persisted.IsValid());
    BOOST_REQUIRE_EQUAL(truncated_persisted.entries.size(), 2U);

    auto restored_truncated = ShieldedAccountRegistryState::RestorePersisted(truncated_persisted);
    BOOST_REQUIRE(restored_truncated.has_value());
    BOOST_REQUIRE(restored_truncated->MaterializeEntry(0).has_value());
    BOOST_REQUIRE(restored_truncated->MaterializeEntry(1).has_value());

    auto stale_restored = ShieldedAccountRegistryState::RestorePersisted(full_persisted);
    BOOST_REQUIRE(stale_restored.has_value());
    BOOST_CHECK(!stale_restored->MaterializeEntry(2).has_value());
    BOOST_CHECK(!stale_restored->CanMaterializeAllEntries());
}

BOOST_AUTO_TEST_CASE(registry_non_pruning_truncate_preserves_shared_externalized_payloads)
{
    RegistryPayloadStoreGuard payload_store_guard(
        m_path_root / "registry_payload_store_non_pruning_truncate");

    const auto first_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x97));
    const auto second_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x98));
    const auto third_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x99));
    BOOST_REQUIRE(first_leaf.has_value());
    BOOST_REQUIRE(second_leaf.has_value());
    BOOST_REQUIRE(third_leaf.has_value());

    ShieldedAccountRegistryState registry_state =
        ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const std::vector<ShieldedAccountLeaf> leaves{*first_leaf, *second_leaf, *third_leaf};
    BOOST_REQUIRE(
        registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    ShieldedAccountRegistryState history_cursor = registry_state;
    BOOST_REQUIRE(history_cursor.Truncate(
        2, ShieldedAccountRegistryState::PayloadPruneMode::KEEP));
    BOOST_CHECK_EQUAL(history_cursor.Size(), 2U);

    BOOST_REQUIRE(registry_state.MaterializeEntry(2).has_value());
    BOOST_CHECK(registry_state.CanMaterializeAllEntries());
}

BOOST_AUTO_TEST_CASE(registry_smaller_snapshot_restore_prunes_stale_externalized_payloads)
{
    RegistryPayloadStoreGuard payload_store_guard(
        m_path_root / "registry_payload_store_restore_prune");

    const auto first_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x94));
    const auto second_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x95));
    const auto third_leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(0x96));
    BOOST_REQUIRE(first_leaf.has_value());
    BOOST_REQUIRE(second_leaf.has_value());
    BOOST_REQUIRE(third_leaf.has_value());

    ShieldedAccountRegistryState registry_state =
        ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    const std::vector<ShieldedAccountLeaf> leaves{*first_leaf, *second_leaf, *third_leaf};
    BOOST_REQUIRE(
        registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    const auto full_snapshot = registry_state.ExportSnapshot();
    const auto full_persisted = registry_state.ExportPersistedSnapshot();
    BOOST_REQUIRE(full_snapshot.IsValid());
    BOOST_REQUIRE(full_persisted.IsValid());
    BOOST_REQUIRE_EQUAL(full_snapshot.entries.size(), 3U);

    auto smaller_snapshot = full_snapshot;
    smaller_snapshot.entries.pop_back();
    BOOST_REQUIRE(smaller_snapshot.IsValid());

    auto restored_smaller = ShieldedAccountRegistryState::Restore(smaller_snapshot);
    BOOST_REQUIRE(restored_smaller.has_value());
    BOOST_CHECK_EQUAL(restored_smaller->Size(), 2U);
    BOOST_REQUIRE(restored_smaller->MaterializeEntry(0).has_value());
    BOOST_REQUIRE(restored_smaller->MaterializeEntry(1).has_value());

    auto stale_restored = ShieldedAccountRegistryState::RestorePersisted(full_persisted);
    BOOST_REQUIRE(stale_restored.has_value());
    BOOST_CHECK(!stale_restored->MaterializeEntry(2).has_value());
    BOOST_CHECK(!stale_restored->CanMaterializeAllEntries());
}

BOOST_AUTO_TEST_CASE(registry_truncate_physically_compacts_externalized_payload_store)
{
    const fs::path db_path = m_path_root / "registry_payload_store_compaction";
    ShieldedAccountRegistryState::ResetPayloadStore();
    BOOST_REQUIRE(ShieldedAccountRegistryState::ConfigurePayloadStore(
        db_path,
        1 << 20,
        /*memory_only=*/false,
        /*wipe_data=*/true,
        DBOptions{.max_file_size = 16 << 10}));

    ShieldedAccountRegistryPersistedSnapshot persisted_snapshot;
    {
        ShieldedAccountRegistryState registry_state =
            ShieldedAccountRegistryState::WithConfiguredPayloadStore();
        std::vector<ShieldedAccountLeaf> leaves;
        leaves.reserve(192);
        for (int seed = 0; seed < 192; ++seed) {
            auto leaf = BuildDirectSendAccountLeaf(MakeDirectOutput(static_cast<unsigned char>(seed)));
            BOOST_REQUIRE(leaf.has_value());
            leaves.push_back(*leaf);
        }
        BOOST_REQUIRE(
            registry_state.Append(Span<const ShieldedAccountLeaf>{leaves.data(), leaves.size()}));
        persisted_snapshot = registry_state.ExportPersistedSnapshot();
        BOOST_REQUIRE(persisted_snapshot.IsValid());
    }
    ShieldedAccountRegistryState::ResetPayloadStore();

    constexpr uint8_t DB_ACCOUNT_REGISTRY_PAYLOAD{static_cast<uint8_t>('P')};
    const auto stale_range_begin = std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, uint64_t{8});
    const auto stale_range_end =
        std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, std::numeric_limits<uint64_t>::max());
    size_t stale_bytes_before{0};
    {
        CDBWrapper db({.path = db_path,
                       .cache_bytes = 1 << 20,
                       .memory_only = false,
                       .wipe_data = false,
                       .obfuscate = true,
                       .options = DBOptions{.max_file_size = 16 << 10}});
        stale_bytes_before = db.EstimateSize(stale_range_begin, stale_range_end);
    }
    BOOST_REQUIRE_GT(stale_bytes_before, 0U);

    BOOST_REQUIRE(ShieldedAccountRegistryState::ConfigurePayloadStore(
        db_path,
        1 << 20,
        /*memory_only=*/false,
        /*wipe_data=*/false,
        DBOptions{.max_file_size = 16 << 10}));
    {
        auto restored_registry = ShieldedAccountRegistryState::RestorePersisted(persisted_snapshot);
        BOOST_REQUIRE(restored_registry.has_value());
        BOOST_REQUIRE(restored_registry->Truncate(8));
    }
    ShieldedAccountRegistryState::ResetPayloadStore();

    size_t stale_bytes_after{0};
    {
        CDBWrapper db({.path = db_path,
                       .cache_bytes = 1 << 20,
                       .memory_only = false,
                       .wipe_data = false,
                       .obfuscate = true,
                       .options = DBOptions{.max_file_size = 16 << 10}});
        stale_bytes_after = db.EstimateSize(stale_range_begin, stale_range_end);
    }

    BOOST_CHECK_LT(stale_bytes_after, stale_bytes_before);
}

BOOST_AUTO_TEST_CASE(output_account_leaf_collectors_cover_all_transaction_families)
{
    const uint256 ingress_binding{0x71};
    const uint256 egress_binding{0x72};
    const uint256 egress_output_binding{0x73};
    const uint256 rebalance_binding{0x74};

    const auto direct_output = MakeDirectOutput(0x51);
    const auto ingress_output = MakeIngressReserveOutput(0x52, ingress_binding, 0);
    const auto egress_output = MakeEgressOutput(0x53, egress_output_binding, 0);
    const auto rebalance_output = MakeRebalanceOutput(0x54, 0);

    CShieldedBundle direct_bundle;
    direct_bundle.v2_bundle.emplace();
    direct_bundle.v2_bundle->header.family_id = shielded::v2::TransactionFamily::V2_SEND;
    shielded::v2::SendPayload direct_payload;
    direct_payload.outputs = {direct_output};
    direct_bundle.v2_bundle->payload = direct_payload;

    CShieldedBundle ingress_bundle;
    ingress_bundle.v2_bundle.emplace();
    ingress_bundle.v2_bundle->header.family_id = shielded::v2::TransactionFamily::V2_INGRESS_BATCH;
    shielded::v2::IngressBatchPayload ingress_payload;
    ingress_payload.settlement_binding_digest = ingress_binding;
    ingress_payload.reserve_outputs = {ingress_output};
    ingress_bundle.v2_bundle->payload = ingress_payload;

    CShieldedBundle egress_bundle;
    egress_bundle.v2_bundle.emplace();
    egress_bundle.v2_bundle->header.family_id = shielded::v2::TransactionFamily::V2_EGRESS_BATCH;
    shielded::v2::EgressBatchPayload egress_payload;
    egress_payload.settlement_binding_digest = egress_binding;
    egress_payload.output_binding_digest = egress_output_binding;
    egress_payload.outputs = {egress_output};
    egress_bundle.v2_bundle->payload = egress_payload;

    CShieldedBundle rebalance_bundle;
    rebalance_bundle.v2_bundle.emplace();
    rebalance_bundle.v2_bundle->header.family_id = shielded::v2::TransactionFamily::V2_REBALANCE;
    shielded::v2::RebalancePayload rebalance_payload;
    rebalance_payload.settlement_binding_digest = rebalance_binding;
    rebalance_payload.reserve_outputs = {rebalance_output};
    rebalance_bundle.v2_bundle->payload = rebalance_payload;

    const auto direct_expected = BuildDirectSendAccountLeaf(direct_output);
    const auto ingress_expected = BuildIngressAccountLeaf(ingress_output, ingress_binding);
    const auto egress_expected =
        BuildEgressAccountLeaf(egress_output, egress_binding, egress_output_binding);
    const auto rebalance_expected = BuildRebalanceAccountLeaf(rebalance_output, rebalance_binding);
    BOOST_REQUIRE(direct_expected.has_value());
    BOOST_REQUIRE(ingress_expected.has_value());
    BOOST_REQUIRE(egress_expected.has_value());
    BOOST_REQUIRE(rebalance_expected.has_value());

    const auto direct_collected = CollectShieldedOutputAccountLeafCommitments(direct_bundle);
    const auto ingress_collected = CollectShieldedOutputAccountLeafCommitments(ingress_bundle);
    const auto egress_collected = CollectShieldedOutputAccountLeafCommitments(egress_bundle);
    const auto rebalance_collected = CollectShieldedOutputAccountLeafCommitments(rebalance_bundle);
    BOOST_REQUIRE(direct_collected.has_value());
    BOOST_REQUIRE(ingress_collected.has_value());
    BOOST_REQUIRE(egress_collected.has_value());
    BOOST_REQUIRE(rebalance_collected.has_value());
    BOOST_REQUIRE_EQUAL(direct_collected->size(), 1U);
    BOOST_REQUIRE_EQUAL(ingress_collected->size(), 1U);
    BOOST_REQUIRE_EQUAL(egress_collected->size(), 1U);
    BOOST_REQUIRE_EQUAL(rebalance_collected->size(), 1U);

    BOOST_CHECK_EQUAL(direct_collected->front(), ComputeShieldedAccountLeafCommitment(*direct_expected));
    BOOST_CHECK_EQUAL(ingress_collected->front(), ComputeShieldedAccountLeafCommitment(*ingress_expected));
    BOOST_CHECK_EQUAL(egress_collected->front(), ComputeShieldedAccountLeafCommitment(*egress_expected));
    BOOST_CHECK_EQUAL(rebalance_collected->front(), ComputeShieldedAccountLeafCommitment(*rebalance_expected));
}

BOOST_AUTO_TEST_SUITE_END()
