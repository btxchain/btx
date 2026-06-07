// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/recovery_exit.h>

#include <hash.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <shielded/merkle_tree.h>
#include <shielded/smile2/wallet_bridge.h>
#include <span.h>
#include <streams.h>

#include <exception>
#include <ios>
#include <limits>
#include <optional>

namespace shielded::recovery {

namespace {
// Same hash the v2 bundle uses for key-hash binding: SHA256 of the raw bytes, no domain prefix.
[[nodiscard]] uint256 HashKeyBytes(const std::vector<unsigned char>& bytes)
{
    HashWriter hw;
    hw.write(AsBytes(Span<const unsigned char>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

// Reconstruct the legacy note the claim describes (memo is not part of the v1 commitment).
[[nodiscard]] ShieldedNote NoteFromClaim(const RecoveryExitClaim& claim)
{
    ShieldedNote note;
    note.value = claim.value;
    note.recipient_pk_hash = claim.recipient_pk_hash;
    note.rho = claim.rho;
    note.rcm = claim.rcm;
    return note;
}
} // namespace

uint256 ComputeRecoveryExitBindingHash(const uint256& commitment,
                                       const uint256& nullifier,
                                       CAmount value,
                                       const uint256& tx_transparent_binding)
{
    // SHA256("BTX_RecoveryExit_Binding_V1" || cm || nf || LE64(value) || tx_transparent_binding).
    // (int64_t)value streams via ser_writedata64 == WriteLE64, the same LE64 idiom the note commitment uses.
    HashWriter hw;
    hw << std::string{"BTX_RecoveryExit_Binding_V1"};
    hw << commitment;
    hw << nullifier;
    hw << static_cast<int64_t>(value);
    hw << tx_transparent_binding;
    return hw.GetSHA256();
}

uint256 ComputeRecoveryExitTransparentBinding(Span<const CTxOut> vout)
{
    HashWriter hw;
    hw << std::string{"BTX_RecoveryExit_TransparentBinding_V1"};
    hw << static_cast<uint64_t>(vout.size());
    for (const CTxOut& out : vout) {
        hw << out.nValue;        // CAmount(int64) LE
        hw << out.scriptPubKey;  // CScript: CompactSize length prefix + raw bytes
    }
    return hw.GetSHA256();
}

bool VerifyRecoveryExitOwnership(const RecoveryExitClaim& claim,
                                 const uint256& binding_hash)
{
    // Mirror the shielded v2 lifecycle-control verification path exactly: shielded v2 keys are ML-DSA-44.
    // CPQPubKey's constructor never throws; Verify() returns false on a malformed pubkey (size mismatch)
    // or a bad signature. Default slhdsa_fips205=false (no SLH-DSA in the shielded v2 pubkey path).
    return CPQPubKey{PQAlgorithm::ML_DSA_44,
                     Span<const unsigned char>{claim.spend_pubkey.data(), claim.spend_pubkey.size()}}
        .Verify(binding_hash,
                Span<const unsigned char>{claim.ownership_sig.data(), claim.ownership_sig.size()});
}

bool VerifyRecoveryExitMembership(const RecoveryExitClaim& claim,
                                  const uint256& commitment,
                                  const uint256& frozen_root,
                                  std::string& reject_reason)
{
    // Fail-closed if the caller cannot supply either the pinned frozen root or the immutable live
    // post-sunset root.
    if (frozen_root.IsNull()) {
        reject_reason = "bad-recovery-exit-no-frozen-root";
        return false;
    }
    shielded::ShieldedMerkleWitness witness;
    try {
        DataStream ss{claim.membership_proof};
        ss >> witness;
    } catch (const std::exception&) {
        reject_reason = "bad-recovery-exit-bad-membership-proof";
        return false;
    }
    if (!witness.Verify(commitment, frozen_root)) {
        reject_reason = "bad-recovery-exit-membership";
        return false;
    }
    return true;
}

bool DeriveRecoveryExitIdentifiers(const RecoveryExitClaim& claim,
                                   RecoveryExitIdentifiers& out,
                                   std::string& reject_reason)
{
    if (claim.spend_pubkey.empty()) {
        reject_reason = "bad-recovery-exit-missing-pubkey";
        return false;
    }
    // Bind the revealed pubkey to the note: recipient_pk_hash == HashBytes(spend_pubkey).
    if (HashKeyBytes(claim.spend_pubkey) != claim.recipient_pk_hash) {
        reject_reason = "bad-recovery-exit-pubkey-binding";
        return false;
    }
    if (!MoneyRange(claim.value) || claim.value <= 0) {
        reject_reason = "bad-recovery-exit-value";
        return false;
    }
    const ShieldedNote note = NoteFromClaim(claim);
    out.commitment = note.GetCommitment();
    // Consensus DERIVES the exact normal-path nullifier from the NOTE itself (no claimant-supplied value,
    // no private key) — the same deterministic note->SMILE2 derivation a post-sunset V2_SEND unshield uses.
    // Byte-identical to what the normal path records => shared-set dedup closes the cross-path double-spend.
    const std::optional<uint256> nf =
        smile2::wallet::ComputeSmileNullifierFromNote(smile2::wallet::SMILE_GLOBAL_SEED, note);
    if (!nf.has_value() || nf->IsNull()) {
        // The note is not eligible for a consensus-derivable SMILE2 nullifier; recovery is invalid for it
        // until a reviewed derivation exists (never guess a nullifier).
        reject_reason = "bad-recovery-exit-no-smile-nullifier";
        return false;
    }
    out.nullifier = *nf;
    if (out.commitment.IsNull()) {
        reject_reason = "bad-recovery-exit-derivation";
        return false;
    }
    return true;
}

bool CheckRecoveryExitClaim(const RecoveryExitClaim& claim,
                            const RecoveryExitConstraints& c,
                            RecoveryExitIdentifiers& out,
                            std::string& reject_reason)
{
    // Fork gate: disabled unless an activation height is set and reached (and never before the sunset).
    if (c.activation_height == std::numeric_limits<int32_t>::max() ||
        c.validation_height < c.activation_height) {
        reject_reason = "bad-recovery-exit-not-active";
        return false;
    }
    // Bounded lifetime: only while the frozen pool still holds value, and before any fixed expiry.
    if (c.pool_balance <= 0) {
        reject_reason = "bad-recovery-exit-pool-empty";
        return false;
    }
    if (c.expiry_height > 0 && c.validation_height >= c.expiry_height) {
        reject_reason = "bad-recovery-exit-expired";
        return false;
    }
    // Pure transparent exit: recover exactly the note's value to transparent, no shielded outputs.
    if (!MoneyRange(claim.value) || claim.value <= 0) {
        reject_reason = "bad-recovery-exit-value";
        return false;
    }
    if (c.shielded_output_count != 0) {
        reject_reason = "bad-recovery-exit-has-shielded-output";
        return false;
    }
    if (c.value_balance != claim.value) {
        reject_reason = "bad-recovery-exit-value-balance";
        return false;
    }
    if (c.fee < 0) {
        reject_reason = "bad-recovery-exit-fee";
        return false;
    }
    if (c.value_balance <= c.fee) {
        reject_reason = "bad-recovery-exit-not-outflow";
        return false;
    }
    if (c.transparent_out != claim.value - c.fee) {
        reject_reason = "bad-recovery-exit-transparent-mismatch";
        return false;
    }
    // Ownership: a PQ signature under spend_pubkey over the claim binding (integration-verified) proves
    // the claimant controls the note — without revealing any key.
    if (!c.ownership_verified) {
        reject_reason = "bad-recovery-exit-ownership";
        return false;
    }
    // Pre-snapshot membership: cm must have existed in the frozen 125,000 commitment tree (blocks
    // fabricated notes); verified by the integration layer against the consensus-pinned root.
    if (!c.membership_verified) {
        reject_reason = "bad-recovery-exit-membership";
        return false;
    }
    // Derive both identifiers from the revealed note + key.
    if (!DeriveRecoveryExitIdentifiers(claim, out, reject_reason)) {
        return false;
    }
    // Single-claim: neither the commitment nor the EXACT canonical nullifier may already be retired.
    // The nullifier check is the cross-path / pre-sunset-spent closure (shared NullifierSet); the
    // commitment check blocks double-recovery.
    if (c.nullifier_already_spent) {
        reject_reason = "bad-recovery-exit-nullifier-spent";
        return false;
    }
    if (c.commitment_already_claimed) {
        reject_reason = "bad-recovery-exit-commitment-claimed";
        return false;
    }
    return true;
}

} // namespace shielded::recovery
