// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_WALLET_BRIDGE_H
#define BTX_SHIELDED_SMILE2_WALLET_BRIDGE_H

#include <shielded/note.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace smile2::wallet {

/**
 * Derive a SMILE key pair from a note's secret material.
 *
 * Unlike the commitment-derived placeholder above, this uses the note's
 * secret rho/rcm material so the resulting spend secret is not publicly
 * reconstructible from the note commitment alone.
 */
SmileKeyPair DeriveSmileKeyPairFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note);

struct SmileRingMember {
    uint256 note_commitment;
    SmilePublicKey public_key;
    BDLOPCommitment public_coin;
    uint256 account_leaf_commitment;

    [[nodiscard]] bool IsValid() const;
};

/**
 * Build a public SMILE ring member from a fully decrypted note.
 *
 * The public key and public coin are derived from the note's secret rho/rcm
 * material so only the sender and recipient can reconstruct the spending
 * secret, while the verifier consumes the explicit public account data.
 */
std::optional<SmileRingMember> BuildRingMemberFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note);

std::optional<SmileRingMember> BuildRingMemberFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note,
    const uint256& note_commitment);
std::optional<SmileRingMember> BuildRingMemberFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note,
    const uint256& note_commitment,
    const uint256& account_leaf_commitment);

std::optional<SmileRingMember> BuildRingMemberFromCompactPublicAccount(
    const std::array<uint8_t, 32>& global_seed,
    const uint256& note_commitment,
    const CompactPublicAccount& account);
std::optional<SmileRingMember> BuildRingMemberFromCompactPublicAccount(
    const std::array<uint8_t, 32>& global_seed,
    const uint256& note_commitment,
    const CompactPublicAccount& account,
    const uint256& account_leaf_commitment);

std::optional<CompactPublicAccount> BuildCompactPublicAccountFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note);

[[nodiscard]] SmilePolyVec DerivePublicCoinOpeningFromNote(const ShieldedNote& note);

[[nodiscard]] BDLOPCommitment BuildPublicCoinFromNote(const ShieldedNote& note);

[[nodiscard]] std::optional<uint256> ComputeSmileNullifierFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note);

/**
 * Build the public anonymity set from explicit ring members.
 */
std::vector<SmilePublicKey> BuildAnonymitySet(Span<const SmileRingMember> ring_members);

struct SmileInputMaterial {
    ShieldedNote note;
    uint256 note_commitment;
    uint256 account_leaf_commitment;
    size_t ring_index{0};  // position of real input in the anonymity set
};

/** Result of a SMILE proof creation.
 *  proof_bytes contains the core proof (without output coins).
 *  output_coins are transmitted alongside the proof in the
 *  V2SendWitness, but are NOT part of the proof serialization itself.
 *  Prover public keys are no longer needed under the current experimental
 *  commitment-derived placeholder model, because BuildAnonymitySet can
 *  reconstruct matching public keys directly from the public commitments.
 *  That placeholder is exactly what the current SMILE-default work is
 *  removing before launch. */
struct SmileProofResult {
    std::vector<uint8_t> proof_bytes;
    std::vector<BDLOPCommitment> output_coins;
};

/**
 * Create a SMILE CT proof from wallet transaction data.
 *
 * Converts wallet-level transaction structures into SMILE proof inputs,
 * generates the proof, and returns a SmileProofResult containing the
 * serialized core proof bytes plus output coins (which are transmitted
 * separately in the witness, not inside the proof).
 *
 * @param global_seed         A matrix seed
 * @param inputs              Per-input decrypted notes and real ring positions
 * @param outputs             Per-output decrypted notes
 * @param ring_members        Explicit public ring members for the anonymity set
 * @param rng_entropy         32 bytes of random entropy for proof generation
 * @param[out] serial_hashes  Output: nullifier hashes for each input
 * @return SmileProofResult with core proof bytes + auxiliary data, or nullopt on failure
 */
std::optional<SmileProofResult> CreateSmileProof(
    const std::array<uint8_t, 32>& global_seed,
    const std::vector<SmileInputMaterial>& inputs,
    const std::vector<ShieldedNote>& outputs,
    Span<const SmileRingMember> ring_members,
    Span<const uint8_t> rng_entropy,
    std::vector<uint256>& serial_hashes,
    int64_t public_fee = 0,
    SmileProofCodecPolicy codec_policy = SmileProofCodecPolicy::CANONICAL_NO_RICE,
    bool bind_anonset_context = false);

/** Well-known global seed for the SMILE A matrix.
 *  Derived from SHA256("BTX-SMILE-V2-GLOBAL-MATRIX-SEED-V1"). */
extern const std::array<uint8_t, 32> SMILE_GLOBAL_SEED;

} // namespace smile2::wallet

#endif // BTX_SHIELDED_SMILE2_WALLET_BRIDGE_H
