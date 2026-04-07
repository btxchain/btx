// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/matrict.h>

#include <crypto/timing_safe.h>
#include <hash.h>
#include <logging.h>
#include <shielded/lattice/sampling.h>
#include <support/cleanse.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>

namespace shielded::ringct {
namespace {

[[nodiscard]] bool UseChainBoundBindingContext(const Consensus::Params& consensus, int32_t validation_height)
{
    return consensus.IsShieldedMatRiCTDisabled(validation_height);
}

[[nodiscard]] uint32_t BindingForkHeight(const Consensus::Params& consensus)
{
    const int32_t disable_height = consensus.nShieldedMatRiCTDisableHeight;
    if (disable_height < 0 || disable_height == std::numeric_limits<int32_t>::max()) {
        return 0;
    }
    return static_cast<uint32_t>(disable_height);
}

[[nodiscard]] lattice::PolyVec DeriveBlindFromNote(const ShieldedNote& note,
                                                    const char* domain,
                                                    uint32_t index)
{
    HashWriter hw;
    hw << std::string{domain};
    hw << index;
    hw << note.recipient_pk_hash;
    hw << note.rho;
    hw << note.rcm;
    hw << note.value;
    const uint256 seed = hw.GetSHA256();
    return lattice::ExpandUniformVec(
        Span<const unsigned char>{seed.begin(), uint256::size()},
        lattice::MODULE_RANK,
        12288 + index * 16);
}

[[nodiscard]] uint256 ComputeProofChallenge(const MatRiCTProof& proof, CAmount fee, const uint256& tx_binding_hash)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_Proof_V2"};
    hw << proof.ring_signature.challenge_seed;
    hw << proof.balance_proof.transcript_hash;
    for (const auto& rp : proof.output_range_proofs) {
        hw << rp.transcript_hash;
    }
    hw << proof.output_note_commitments;
    hw << fee;
    hw << tx_binding_hash;
    return hw.GetSHA256();
}

void CleanseInputSecrets(std::vector<lattice::PolyVec>& input_secrets)
{
    for (auto& secret : input_secrets) {
        if (!secret.empty()) {
            memory_cleanse(secret.data(), secret.size() * sizeof(lattice::Poly256));
        }
    }
}

} // namespace

template <typename TxType>
uint256 ComputeMatRiCTBindingHashImpl(const TxType& tx)
{
    if (!tx.HasShieldedBundle()) return uint256{};

    CMutableTransaction tx_stripped{tx};
    tx_stripped.shielded_bundle.proof.clear();
    for (auto& input : tx_stripped.shielded_bundle.shielded_inputs) {
        input.ring_positions.clear();
    }
    return tx_stripped.GetHash();
}

template <typename TxType>
uint256 ComputeMatRiCTBindingHashImpl(const TxType& tx,
                                      const Consensus::Params& consensus,
                                      int32_t validation_height)
{
    const uint256 stripped_hash = ComputeMatRiCTBindingHashImpl(tx);
    if (stripped_hash.IsNull() || !UseChainBoundBindingContext(consensus, validation_height)) {
        return stripped_hash;
    }

    HashWriter hw;
    hw << std::string{"BTX_Shielded_MatRiCT_Binding_V2"};
    hw << consensus.hashGenesisBlock;
    hw << BindingForkHeight(consensus);
    hw << stripped_hash;
    return hw.GetSHA256();
}

uint256 ComputeMatRiCTBindingHash(const CTransaction& tx)
{
    return ComputeMatRiCTBindingHashImpl(tx);
}

uint256 ComputeMatRiCTBindingHash(const CMutableTransaction& tx)
{
    return ComputeMatRiCTBindingHashImpl(tx);
}

uint256 ComputeMatRiCTBindingHash(const CTransaction& tx,
                                  const Consensus::Params& consensus,
                                  int32_t validation_height)
{
    return ComputeMatRiCTBindingHashImpl(tx, consensus, validation_height);
}

uint256 ComputeMatRiCTBindingHash(const CMutableTransaction& tx,
                                  const Consensus::Params& consensus,
                                  int32_t validation_height)
{
    return ComputeMatRiCTBindingHashImpl(tx, consensus, validation_height);
}

size_t MatRiCTProof::GetSerializedSize() const
{
    return ::GetSerializeSize(*this);
}

bool MatRiCTProof::IsValid() const
{
    if (input_commitments.empty()) return false;
    if (output_commitments.size() != output_range_proofs.size()) return false;
    if (output_note_commitments.size() != output_commitments.size()) return false;
    if (challenge_seed.IsNull()) return false;

    for (const auto& c : input_commitments) {
        if (!c.IsValid()) return false;
    }
    for (const auto& c : output_commitments) {
        if (!c.IsValid()) return false;
    }
    for (const auto& rp : output_range_proofs) {
        if (!rp.IsValid()) return false;
    }
    if (!balance_proof.IsValid()) return false;
    return true;
}

bool CreateMatRiCTProof(MatRiCTProof& proof,
                        const std::vector<ShieldedNote>& input_notes,
                        const std::vector<ShieldedNote>& output_notes,
                        Span<const uint256> output_note_commitments,
                        const std::vector<Nullifier>& input_nullifiers,
                        const std::vector<std::vector<uint256>>& ring_members,
                        const std::vector<size_t>& real_indices,
                        Span<const unsigned char> spending_key,
                        CAmount fee,
                        const uint256& tx_binding_hash,
                        Span<const unsigned char> rng_entropy)
{
    if (!output_note_commitments.empty() &&
        output_note_commitments.size() != output_notes.size()) {
        LogPrintf("CreateMatRiCTProof failed: output note commitment count mismatch (%u != %u)\n",
                  static_cast<unsigned int>(output_note_commitments.size()),
                  static_cast<unsigned int>(output_notes.size()));
        return false;
    }

    const bool use_explicit_output_note_commitments = !output_note_commitments.empty();
    const auto get_output_note_commitment = [&](size_t index) -> uint256 {
        return use_explicit_output_note_commitments
            ? output_note_commitments[index]
            : output_notes[index].GetCommitment();
    };

    if (use_explicit_output_note_commitments) {
        for (size_t i = 0; i < output_note_commitments.size(); ++i) {
            if (output_note_commitments[i].IsNull()) {
                LogPrintf("CreateMatRiCTProof failed: null explicit output note commitment at index %u\n",
                          static_cast<unsigned int>(i));
                return false;
            }
        }
    }

    proof.input_commitments.clear();
    proof.output_commitments.clear();
    proof.output_note_commitments.clear();
    proof.output_range_proofs.clear();

    std::vector<CommitmentOpening> input_openings;
    std::vector<CommitmentOpening> output_openings;
    std::vector<lattice::PolyVec> input_secrets;

    input_openings.reserve(input_notes.size());
    output_openings.reserve(output_notes.size());
    input_secrets.reserve(input_notes.size());

    if (input_notes.empty() || output_notes.empty()) {
        LogPrintf("CreateMatRiCTProof failed: empty note set (inputs=%u outputs=%u)\n",
                  static_cast<unsigned int>(input_notes.size()),
                  static_cast<unsigned int>(output_notes.size()));
        return false;
    }
    if (input_nullifiers.size() != input_notes.size()) {
        LogPrintf("CreateMatRiCTProof failed: input nullifier count mismatch (%u != %u)\n",
                  static_cast<unsigned int>(input_nullifiers.size()),
                  static_cast<unsigned int>(input_notes.size()));
        return false;
    }
    if (ring_members.size() != input_notes.size()) {
        LogPrintf("CreateMatRiCTProof failed: ring member set count mismatch (%u != %u)\n",
                  static_cast<unsigned int>(ring_members.size()),
                  static_cast<unsigned int>(input_notes.size()));
        return false;
    }
    if (real_indices.size() != input_notes.size()) {
        LogPrintf("CreateMatRiCTProof failed: real index count mismatch (%u != %u)\n",
                  static_cast<unsigned int>(real_indices.size()),
                  static_cast<unsigned int>(input_notes.size()));
        return false;
    }
    if (spending_key.empty()) {
        LogPrintf("CreateMatRiCTProof failed: empty spending key material\n");
        return false;
    }
    const size_t ring_size = ring_members.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) {
        LogPrintf("CreateMatRiCTProof failed: unsupported ring size %u\n",
                  static_cast<unsigned int>(ring_size));
        return false;
    }
    for (size_t i = 0; i < ring_members.size(); ++i) {
        if (ring_members[i].size() != ring_size) {
            LogPrintf("CreateMatRiCTProof failed: ring[%u] size %u != common ring size %u\n",
                      static_cast<unsigned int>(i),
                      static_cast<unsigned int>(ring_members[i].size()),
                      static_cast<unsigned int>(ring_size));
            return false;
        }
        if (real_indices[i] >= ring_members[i].size()) {
            LogPrintf("CreateMatRiCTProof failed: real index out of range ring[%u] index=%u size=%u\n",
                      static_cast<unsigned int>(i),
                      static_cast<unsigned int>(real_indices[i]),
                      static_cast<unsigned int>(ring_members[i].size()));
            return false;
        }
    }

    for (size_t i = 0; i < input_notes.size(); ++i) {
        if (!input_notes[i].IsValid()) {
            LogPrintf("CreateMatRiCTProof failed: invalid input note at index %u\n",
                      static_cast<unsigned int>(i));
            return false;
        }
        lattice::PolyVec input_secret;
        if (!DeriveInputSecretFromNote(input_secret, spending_key, input_notes[i])) {
            LogPrintf("CreateMatRiCTProof failed: input secret derivation failed at index %u\n",
                      static_cast<unsigned int>(i));
            CleanseInputSecrets(input_secrets);
            return false;
        }
        Nullifier expected_nullifier;
        if (!DeriveInputNullifierFromSecret(expected_nullifier, input_secret, ring_members[i][real_indices[i]])) {
            LogPrintf("CreateMatRiCTProof failed: nullifier derivation from secret failed at index %u\n",
                      static_cast<unsigned int>(i));
            if (!input_secret.empty()) {
                memory_cleanse(input_secret.data(), input_secret.size() * sizeof(lattice::Poly256));
            }
            CleanseInputSecrets(input_secrets);
            return false;
        }
        if (expected_nullifier != input_nullifiers[i]) {
            LogPrintf("CreateMatRiCTProof failed: nullifier mismatch at index %u expected=%s actual=%s\n",
                      static_cast<unsigned int>(i),
                      expected_nullifier.ToString(),
                      input_nullifiers[i].ToString());
            if (!input_secret.empty()) {
                memory_cleanse(input_secret.data(), input_secret.size() * sizeof(lattice::Poly256));
            }
            CleanseInputSecrets(input_secrets);
            return false;
        }
        input_secrets.push_back(std::move(input_secret));

        CommitmentOpening opening;
        opening.value = input_notes[i].value;
        opening.blind = DeriveBlindFromNote(input_notes[i], "BTX_MatRiCT_InputBlind_V1", static_cast<uint32_t>(i));
        input_openings.push_back(opening);
        proof.input_commitments.push_back(Commit(opening.value, opening.blind));
    }

    for (size_t i = 0; i < output_notes.size(); ++i) {
        if (!output_notes[i].IsValid()) {
            LogPrintf("CreateMatRiCTProof failed: invalid output note at index %u\n",
                      static_cast<unsigned int>(i));
            return false;
        }

        const uint256 bound_note_commitment = get_output_note_commitment(i);
        if (bound_note_commitment.IsNull()) {
            LogPrintf("CreateMatRiCTProof failed: output note commitment is null at index %u\n",
                      static_cast<unsigned int>(i));
            CleanseInputSecrets(input_secrets);
            return false;
        }

        CommitmentOpening opening;
        opening.value = output_notes[i].value;
        opening.blind = DeriveBlindFromNote(output_notes[i], "BTX_MatRiCT_OutputBlind_V1", static_cast<uint32_t>(i));
        output_openings.push_back(opening);

        const Commitment commitment = Commit(opening.value, opening.blind);
        proof.output_commitments.push_back(commitment);
        proof.output_note_commitments.push_back(bound_note_commitment);

        RangeProof rp;
        if (!CreateRangeProof(rp, opening, commitment)) {
            LogPrintf("CreateMatRiCTProof failed: range proof creation failed at output index %u\n",
                      static_cast<unsigned int>(i));
            CleanseInputSecrets(input_secrets);
            return false;
        }
        proof.output_range_proofs.push_back(std::move(rp));
    }

    if (!CreateBalanceProof(proof.balance_proof, input_openings, output_openings, fee, tx_binding_hash)) {
        LogPrintf("CreateMatRiCTProof failed: balance proof creation failed\n");
        CleanseInputSecrets(input_secrets);
        return false;
    }

    const uint256 message_hash = RingSignatureMessageHash(proof.input_commitments,
                                                          proof.output_commitments,
                                                          fee,
                                                          input_nullifiers,
                                                          tx_binding_hash);
    const bool allow_duplicate_ring_members = std::any_of(
        ring_members.begin(),
        ring_members.end(),
        [](const std::vector<uint256>& ring) {
            std::set<uint256> unique_members;
            for (const auto& member : ring) {
                unique_members.insert(member);
            }
            return unique_members.size() < ring.size();
        });
    if (!CreateRingSignature(proof.ring_signature,
                             ring_members,
                             real_indices,
                             input_secrets,
                             message_hash,
                             rng_entropy,
                             allow_duplicate_ring_members)) {
        LogPrintf("CreateMatRiCTProof failed: ring signature creation failed\n");
        CleanseInputSecrets(input_secrets);
        return false;
    }
    CleanseInputSecrets(input_secrets);

    proof.challenge_seed = ComputeProofChallenge(proof, fee, tx_binding_hash);
    return true;
}

bool CreateMatRiCTProof(MatRiCTProof& proof,
                        const std::vector<ShieldedNote>& input_notes,
                        const std::vector<ShieldedNote>& output_notes,
                        const std::vector<Nullifier>& input_nullifiers,
                        const std::vector<std::vector<uint256>>& ring_members,
                        const std::vector<size_t>& real_indices,
                        Span<const unsigned char> spending_key,
                        CAmount fee,
                        const uint256& tx_binding_hash,
                        Span<const unsigned char> rng_entropy)
{
    std::vector<uint256> derived_output_note_commitments;
    derived_output_note_commitments.reserve(output_notes.size());
    for (const auto& note : output_notes) {
        derived_output_note_commitments.push_back(note.GetCommitment());
    }

    return CreateMatRiCTProof(proof,
                              input_notes,
                              output_notes,
                              Span<const uint256>{derived_output_note_commitments.data(),
                                                  derived_output_note_commitments.size()},
                              input_nullifiers,
                              ring_members,
                              real_indices,
                              spending_key,
                              fee,
                              tx_binding_hash,
                              rng_entropy);
}

bool VerifyMatRiCTProof(const MatRiCTProof& proof,
                        const std::vector<std::vector<uint256>>& ring_member_commitments,
                        const std::vector<Nullifier>& input_nullifiers,
                        const std::vector<uint256>& output_commitments,
                        CAmount fee,
                        const uint256& tx_binding_hash)
{
    if (!proof.IsValid()) return false;
    if (ring_member_commitments.empty()) return false;
    if (input_nullifiers.size() != proof.input_commitments.size()) return false;
    if (proof.output_note_commitments != output_commitments) return false;
    if (proof.input_commitments.size() != ring_member_commitments.size()) return false;
    const size_t ring_size = ring_member_commitments.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;
    for (const auto& ring : ring_member_commitments) {
        if (ring.size() != ring_size) return false;
    }
    if (!VerifyRingSignatureNullifierBinding(proof.ring_signature, input_nullifiers)) return false;

    const uint256 message_hash = RingSignatureMessageHash(proof.input_commitments,
                                                          proof.output_commitments,
                                                          fee,
                                                          input_nullifiers,
                                                          tx_binding_hash);

    if (!VerifyRingSignature(proof.ring_signature, ring_member_commitments, message_hash)) {
        return false;
    }

    for (size_t i = 0; i < proof.output_range_proofs.size(); ++i) {
        if (!VerifyRangeProof(proof.output_range_proofs[i], proof.output_commitments[i])) {
            return false;
        }
    }

    if (!VerifyBalanceProof(proof.balance_proof,
                            proof.input_commitments,
                            proof.output_commitments,
                            fee,
                            tx_binding_hash)) {
        return false;
    }

    const uint256 expected = ComputeProofChallenge(proof, fee, tx_binding_hash);
    return TimingSafeEqual(expected, proof.challenge_seed);
}

} // namespace shielded::ringct
