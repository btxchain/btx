// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RECOVERY_EXIT — transparent-claim stranded-note recovery (post-125,000).
// See doc/recovery_exit_125000_spec.md.
//
// SAFE ROUTE (per audit): consensus does NOT trust a claimant-supplied nullifier. It DERIVES the exact
// normal-path nullifier from the revealed NOTE itself — `ComputeSmileNullifierFromNote(SMILE_GLOBAL_SEED,
// note)`, the same deterministic note->SMILE2 derivation the post-sunset `V2_SEND` unshield uses — and
// ATOMICALLY retires BOTH the commitment and that nullifier into the SHARED nullifier set. Because the
// derived nullifier is byte-for-byte the one a normal `V2_SEND` spend of this note would reveal, a note
// spent on EITHER path collides in the shared set — closing cross-path AND pre-sunset-spent double-spends.
//
// Crucially, the SMILE2 nullifier is a function of the note alone (no private key), so the claim does NOT
// reveal any spend key — ownership is proven by a PQ signature under the note's pubkey. No sibling-note
// exposure. This module implements the pure derivation + constraint logic; DB retirement, bundle encoding,
// prover, membership proof, and PQ ownership-signature verification are the integration layer (see spec).

#ifndef BTX_SHIELDED_RECOVERY_EXIT_H
#define BTX_SHIELDED_RECOVERY_EXIT_H

#include <consensus/amount.h>
#include <shielded/note.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CTxOut;

namespace shielded::recovery {

/** The revealed claim a RECOVERY_EXIT carries. Everything here is public on the wire. */
struct RecoveryExitClaim {
    CAmount value{0};
    uint256 recipient_pk_hash;                 //!< SHA256(spend_pubkey); commits the note to its key
    uint256 rho;
    uint256 rcm;
    std::vector<unsigned char> spend_pubkey;   //!< full PQ public key; HashBytes(spend_pubkey)==recipient_pk_hash
    std::vector<unsigned char> ownership_sig;  //!< PQ signature by spend_pubkey over the binding hash
    std::vector<unsigned char> membership_proof; //!< serialized ShieldedMerkleWitness proving cm in the frozen tree
    // NOTE: no spend key is revealed. The nullifier is derived from the note alone (SMILE2); ownership is
    // proven by the PQ signature under spend_pubkey over ComputeRecoveryExitBindingHash().
};

/** The message the ownership PQ signature commits to. Binds the claim to its exact payout so the
 *  signature cannot be replayed onto a different recovery or a redirected transparent output:
 *  SHA256("BTX_RecoveryExit_Binding_V1" || cm || nf || LE64(value) || tx_transparent_binding),
 *  where tx_transparent_binding hashes the transaction's transparent outputs (computed by the caller,
 *  identically in the wallet builder and the consensus verifier). */
[[nodiscard]] uint256 ComputeRecoveryExitBindingHash(const uint256& commitment,
                                                     const uint256& nullifier,
                                                     CAmount value,
                                                     const uint256& tx_transparent_binding);

/** Single source of truth for tx_transparent_binding (used identically by the wallet builder and the
 *  consensus verifier so they cannot drift): SHA256("BTX_RecoveryExit_TransparentBinding_V1" ||
 *  LE64(vout.size()) || for each txout: LE64(nValue) || CScript(scriptPubKey)). Binds the exact payout. */
[[nodiscard]] uint256 ComputeRecoveryExitTransparentBinding(Span<const CTxOut> vout);

/** Verify the ownership PQ signature: CPQPubKey(spend_pubkey).Verify(binding_hash, ownership_sig).
 *  Proves the claimant controls the note's key without revealing it. */
[[nodiscard]] bool VerifyRecoveryExitOwnership(const RecoveryExitClaim& claim,
                                               const uint256& binding_hash);

/** Verify the pre-snapshot membership proof: deserialize the ShieldedMerkleWitness from
 *  claim.membership_proof and check it authenticates `commitment` against `frozen_root`. The caller
 *  supplies either a release-pinned shielded note-commitment root for the frozen 125,000 ceiling or the
 *  live tree root after the sunset has made the tree immutable. Returns false (with reason) on a
 *  malformed or non-authenticating proof, or if frozen_root is null. */
[[nodiscard]] bool VerifyRecoveryExitMembership(const RecoveryExitClaim& claim,
                                                const uint256& commitment,
                                                const uint256& frozen_root,
                                                std::string& reject_reason);

/** The two identifiers consensus retires together. */
struct RecoveryExitIdentifiers {
    uint256 commitment;   //!< retired in the spent-commitment set (blocks double-recovery)
    uint256 nullifier;    //!< retired in the SHARED nullifier set (blocks cross-path / pre-spent re-claim)
};

/** Reconstruct the note from the claim, verify the pubkey binds to recipient_pk_hash, and derive BOTH
 *  the commitment and the EXACT canonical normal-exit nullifier
 *  (= ComputeSmileNullifierFromNote(SMILE_GLOBAL_SEED, note), the same one a post-sunset V2_SEND unshield
 *  of this note reveals). Returns false (with reason) if the revealed pubkey does not hash to
 *  recipient_pk_hash, or if the note is not eligible for a consensus-derivable SMILE2 nullifier. */
[[nodiscard]] bool DeriveRecoveryExitIdentifiers(const RecoveryExitClaim& claim,
                                                 RecoveryExitIdentifiers& out,
                                                 std::string& reject_reason);

/** Everything the consensus rule needs beyond the claim itself. */
struct RecoveryExitConstraints {
    CAmount value_balance{0};      //!< bundle state value balance (must equal the recovered value)
    CAmount fee{0};
    CAmount transparent_out{0};    //!< total transparent output value
    uint64_t shielded_output_count{0};
    CAmount pool_balance{0};       //!< current frozen pool balance
    int32_t validation_height{0};
    int32_t activation_height{0};  //!< nShieldedRecoveryExitActivationHeight (disabled = int32 max)
    int32_t expiry_height{0};      //!< <=0 => no fixed expiry (still gated on pool_balance > 0)
    bool ownership_verified{false};         //!< PQ ownership_sig verified under spend_pubkey (integration)
    bool membership_verified{false};        //!< cm proven in the frozen 125,000 commitment tree (integration)
    bool nullifier_already_spent{false};    //!< derived nf already in the SHARED nullifier set
    bool commitment_already_claimed{false}; //!< derived cm already in the spent-commitment set
};

/** Full consensus predicate for a RECOVERY_EXIT. On success, fills `out` with the identifiers the caller
 *  must atomically retire (nullifier into the shared NullifierSet, commitment into the spent-commitment
 *  set). Enforces: fork active; key binding; pure transparent exit (value_balance == value > fee,
 *  nonnegative fee, transparent_out == value - fee, zero shielded outputs); single-claim (neither identifier already
 *  retired); pool_balance > 0 and not past expiry. */
[[nodiscard]] bool CheckRecoveryExitClaim(const RecoveryExitClaim& claim,
                                          const RecoveryExitConstraints& c,
                                          RecoveryExitIdentifiers& out,
                                          std::string& reject_reason);

} // namespace shielded::recovery

#endif // BTX_SHIELDED_RECOVERY_EXIT_H
