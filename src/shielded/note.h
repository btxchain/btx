// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_NOTE_H
#define BTX_SHIELDED_NOTE_H

#include <consensus/amount.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <ios>
#include <vector>

/** Maximum memo size in a shielded note (512 bytes). */
static constexpr size_t MAX_SHIELDED_MEMO_SIZE{512};

/**
 * A shielded note represents a unit of value in the shielded pool.
 *
 * Note commitment:
 *   inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || pk_hash)
 *   cm    = SHA256("BTX_Note_Commit_V1" || inner || rho || rcm)
 *
 * Nullifier:
 *   nf = SHA256("BTX_Note_Nullifier_V1" || spending_key || rho || cm)
 */
struct ShieldedNote {
    CAmount value{0};
    uint256 recipient_pk_hash;  //!< SHA256(full PQ public key)
    uint256 rho;                //!< unique random nonce
    uint256 rcm;                //!< commitment randomness
    std::vector<unsigned char> memo;

    /** Compute the note commitment. Deterministic for fixed inputs. */
    [[nodiscard]] uint256 GetCommitment() const;

    /** Compute the nullifier given spending key bytes. */
    [[nodiscard]] uint256 GetNullifier(Span<const unsigned char> spending_key) const;

    /** Check if the note has valid parameters. */
    [[nodiscard]] bool IsValid() const;

    SERIALIZE_METHODS(ShieldedNote, obj)
    {
        READWRITE(obj.value, obj.recipient_pk_hash, obj.rho, obj.rcm);
        if constexpr (ser_action.ForRead()) {
            uint64_t memo_size{0};
            ::Unserialize(s, COMPACTSIZE(memo_size));
            if (memo_size > MAX_SHIELDED_MEMO_SIZE) {
                throw std::ios_base::failure("ShieldedNote::Unserialize oversized memo");
            }
            obj.memo.resize(memo_size);
            if (memo_size > 0) {
                s.read(AsWritableBytes(Span<unsigned char>{obj.memo.data(), obj.memo.size()}));
            }
        } else {
            const uint64_t memo_size = obj.memo.size();
            if (memo_size > MAX_SHIELDED_MEMO_SIZE) {
                throw std::ios_base::failure("ShieldedNote::Serialize oversized memo");
            }
            ::Serialize(s, COMPACTSIZE(memo_size));
            if (memo_size > 0) {
                s.write(AsBytes(Span<const unsigned char>{obj.memo.data(), obj.memo.size()}));
            }
        }
    }
};

/** True when the note carries the modern SMILE-derivation marker used by the
 * padded bound-note format. Legacy notes return false. */
[[nodiscard]] bool UsesModernShieldedNoteDerivation(const ShieldedNote& note);

/** Apply the modern SMILE-derivation marker to a note in-place. */
void MarkShieldedNoteForModernDerivation(ShieldedNote& note);

using Nullifier = uint256;

#endif // BTX_SHIELDED_NOTE_H
