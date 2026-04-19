// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_adversarial_proof_corpus.h>

#include <core_io.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <shielded/v2_proof.h>
#include <span.h>
#include <streams.h>

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace btx::test::shielded {
namespace {

namespace v2proof = ::shielded::v2::proof;

[[nodiscard]] uint256 DeterministicMutationHash(const CTransaction& tx, std::string_view id)
{
    HashWriter hw;
    hw << std::string{"BTX_ShieldedV2_AdversarialProofCorpus_V1"}
       << tx.GetHash()
       << std::string{id};
    return hw.GetSHA256();
}

[[nodiscard]] std::vector<uint8_t> SerializeWitness(const v2proof::V2SendWitness& witness)
{
    DataStream ds{};
    ds << witness;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

[[nodiscard]] bool DecodeBaseTransaction(const std::string& base_tx_hex,
                                         CMutableTransaction& tx,
                                         std::string& reject_reason)
{
    if (!DecodeHexTx(tx, base_tx_hex)) {
        reject_reason = "invalid-base-tx-hex";
        return false;
    }
    if (!tx.HasShieldedBundle() || !tx.shielded_bundle.v2_bundle.has_value()) {
        reject_reason = "expected-shielded-v2-base-tx";
        return false;
    }
    const auto& bundle = *tx.shielded_bundle.v2_bundle;
    if (!::shielded::v2::BundleHasSemanticFamily(bundle, ::shielded::v2::TransactionFamily::V2_SEND) ||
        !std::holds_alternative<::shielded::v2::SendPayload>(bundle.payload)) {
        reject_reason = "expected-v2-send-base-tx";
        return false;
    }
    return true;
}

template <typename Mutator>
[[nodiscard]] bool AddVariant(AdversarialProofCorpus& corpus,
                              const CMutableTransaction& base_tx,
                              std::string id,
                              std::string description,
                              std::string expected_reject_reason,
                              std::string expected_failure_stage,
                              Mutator&& mutator,
                              std::string& reject_reason)
{
    CMutableTransaction mutated = base_tx;
    if (!mutated.shielded_bundle.v2_bundle.has_value()) {
        reject_reason = "missing-v2-bundle";
        return false;
    }
    auto& bundle = *mutated.shielded_bundle.v2_bundle;
    if (!mutator(mutated, bundle, reject_reason)) {
        if (reject_reason.empty()) reject_reason = "mutation-failed";
        return false;
    }

    const CTransaction immutable_tx{mutated};
    corpus.variants.push_back({
        .id = std::move(id),
        .description = std::move(description),
        .expected_reject_reason = std::move(expected_reject_reason),
        .expected_failure_stage = std::move(expected_failure_stage),
        .tx_hex = EncodeHexTx(immutable_tx),
        .txid_hex = immutable_tx.GetHash().GetHex(),
        .wtxid_hex = immutable_tx.GetWitnessHash().GetHex(),
    });
    return true;
}

} // namespace

std::optional<AdversarialProofCorpus> BuildV2SendAdversarialProofCorpus(
    const std::string& base_tx_hex,
    std::string& reject_reason)
{
    reject_reason.clear();

    CMutableTransaction base_tx;
    if (!DecodeBaseTransaction(base_tx_hex, base_tx, reject_reason)) {
        return std::nullopt;
    }

    const auto& base_bundle = *base_tx.shielded_bundle.v2_bundle;
    auto base_witness = v2proof::ParseV2SendWitness(base_bundle, reject_reason);
    if (!base_witness.has_value()) {
        return std::nullopt;
    }
    if (base_witness->spends.empty()) {
        reject_reason = "missing-v2-send-spend-witness";
        return std::nullopt;
    }
    if (base_witness->use_smile) {
        if (base_witness->smile_proof_bytes.empty()) {
            reject_reason = "missing-v2-send-smile-proof";
            return std::nullopt;
        }
    } else {
        if (base_witness->native_proof.ring_signature.input_proofs.empty() ||
            base_witness->native_proof.ring_signature.input_proofs[0].challenges.empty()) {
            reject_reason = "missing-v2-send-ring-proof";
            return std::nullopt;
        }
    }

    const CTransaction immutable_base_tx{base_tx};
    AdversarialProofCorpus corpus{
        .family_name = "v2_send",
        .base_tx_hex = base_tx_hex,
        .base_txid_hex = immutable_base_tx.GetHash().GetHex(),
        .base_wtxid_hex = immutable_base_tx.GetWitnessHash().GetHex(),
        .variants = {},
    };

    if (!AddVariant(
            corpus,
            base_tx,
            "proof_payload_truncated",
            "Truncate the inline v2_send witness payload by one byte so witness decoding fails.",
            "bad-shielded-proof-encoding",
            "witness_parse",
            [](CMutableTransaction&,
               ::shielded::v2::TransactionBundle& bundle,
               std::string& out_reject) {
                if (bundle.proof_payload.empty()) {
                    out_reject = "missing-proof-payload";
                    return false;
                }
                bundle.proof_payload.pop_back();
                return true;
            },
            reject_reason)) {
        return std::nullopt;
    }

    if (!AddVariant(
            corpus,
            base_tx,
            "proof_payload_appended_junk",
            "Append a trailing byte so witness decoding succeeds but leaves unread payload junk.",
            "bad-shielded-proof-encoding",
            "witness_parse",
            [](CMutableTransaction&,
               ::shielded::v2::TransactionBundle& bundle,
               std::string&) {
                bundle.proof_payload.push_back(0xff);
                return true;
            },
            reject_reason)) {
        return std::nullopt;
    }

    if (!AddVariant(
            corpus,
            base_tx,
            "witness_real_index_oob",
            "Force the spend witness real_index past the ring bound so proof verification rejects it.",
            "bad-shielded-proof",
            "proof_verify",
            [base_witness](CMutableTransaction&,
                           ::shielded::v2::TransactionBundle& bundle,
                           std::string& out_reject) {
                auto witness = *base_witness;
                if (witness.spends.empty()) {
                    out_reject = "missing-v2-send-spend-witness";
                    return false;
                }
                witness.spends[0].real_index =
                    static_cast<uint32_t>(witness.spends[0].ring_positions.size());
                bundle.proof_payload = SerializeWitness(witness);
                return true;
            },
            reject_reason)) {
        return std::nullopt;
    }

    if (!AddVariant(
            corpus,
            base_tx,
            "statement_digest_mismatch",
            "Replace the proof-envelope statement digest so contextual proof binding no longer matches the tx.",
            "bad-shielded-proof",
            "statement_binding",
            [immutable_base_tx](CMutableTransaction&,
                                ::shielded::v2::TransactionBundle& bundle,
                                std::string&) {
                uint256 mutation_digest = DeterministicMutationHash(immutable_base_tx, "statement_digest_mismatch");
                if (mutation_digest == bundle.header.proof_envelope.statement_digest) {
                    mutation_digest = uint256{0xa5};
                }
                bundle.header.proof_envelope.statement_digest = mutation_digest;
                return true;
            },
            reject_reason)) {
        return std::nullopt;
    }

    if (!AddVariant(
            corpus,
            base_tx,
            "ring_challenge_tamper",
            "Overwrite proof bytes while preserving witness structure so proof verification fails.",
            "bad-shielded-proof",
            "proof_verify",
            [base_witness, immutable_base_tx](CMutableTransaction&,
                                              ::shielded::v2::TransactionBundle& bundle,
                                              std::string& out_reject) {
                auto witness = *base_witness;
                if (witness.use_smile) {
                    if (witness.smile_proof_bytes.empty()) {
                        out_reject = "missing-v2-send-smile-proof";
                        return false;
                    }
                    // Flip a byte in the SMILE proof to corrupt it.
                    uint256 tampered = DeterministicMutationHash(immutable_base_tx, "ring_challenge_tamper");
                    const size_t flip_offset = tampered.IsNull() ? 0
                        : static_cast<size_t>(tampered.GetUint64(0) % witness.smile_proof_bytes.size());
                    witness.smile_proof_bytes[flip_offset] ^= 0xff;
                } else {
                    auto& ring_signature = witness.native_proof.ring_signature;
                    if (ring_signature.input_proofs.empty() ||
                        ring_signature.input_proofs[0].challenges.empty()) {
                        out_reject = "missing-v2-send-ring-proof";
                        return false;
                    }
                    uint256 tampered = DeterministicMutationHash(immutable_base_tx, "ring_challenge_tamper");
                    if (tampered == ring_signature.input_proofs[0].challenges[0]) {
                        tampered = uint256{0x5a};
                    }
                    ring_signature.input_proofs[0].challenges[0] = tampered;
                }
                bundle.proof_payload = SerializeWitness(witness);
                return true;
            },
            reject_reason)) {
        return std::nullopt;
    }

    return corpus;
}

} // namespace btx::test::shielded
