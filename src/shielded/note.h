// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_NOTE_H
#define BTX_SHIELDED_NOTE_H

#include <consensus/amount.h>
#include <serialize.h>
#include <shielded/lattice/polyvec.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <ios>
#include <vector>

/** Maximum serialized spend-anchor size in a shielded note. A bound-mode anchor
 *  is a fixed-rank mod-q PolyVec; this caps the trailing v2 field on the wire. */
static constexpr size_t MAX_SHIELDED_SPEND_ANCHOR_SIZE{4096};

struct ShieldedNote;

/** True when the note carries the modern SMILE-derivation marker used by the
 * padded bound-note format. Legacy notes return false. Forward-declared here so
 * ShieldedNote's serializer can gate the trailing v2 spend_anchor on it. */
[[nodiscard]] bool UsesModernShieldedNoteDerivation(const ShieldedNote& note);

/** Maximum memo size in a shielded note (512 bytes). */
static constexpr size_t MAX_SHIELDED_MEMO_SIZE{512};

/**
 * A shielded note represents a unit of value in the shielded pool.
 *
 * Note commitment (legacy v1, empty spend_anchor):
 *   inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || pk_hash)
 *   cm    = SHA256("BTX_Note_Commit_V1" || inner || rho || rcm)
 *
 * Note commitment (v2, non-empty spend_anchor — binds the bound-mode spend anchor):
 *   inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || pk_hash)
 *   cm    = SHA256("BTX_Note_Commit_V2" || inner || rho || rcm || SHA256(spend_anchor))
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
    //! Optional bound-mode spend anchor (serialized PolyVec bytes). Empty => legacy
    //! v1 note. When non-empty the note is a v2 note that binds this anchor into the
    //! commitment. Only round-tripped on the wire for notes carrying the modern
    //! SMILE-derivation marker (see UsesModernShieldedNoteDerivation); legacy notes
    //! serialize byte-identically to v1.
    std::vector<unsigned char> spend_anchor;

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
            // Trailing v2 spend_anchor is present ONLY for notes carrying the modern
            // SMILE-derivation marker. Legacy (unmarked) notes have no trailing bytes,
            // so their wire encoding is byte-identical to the original v1 format.
            obj.spend_anchor.clear();
            if (UsesModernShieldedNoteDerivation(obj)) {
                uint64_t anchor_size{0};
                ::Unserialize(s, COMPACTSIZE(anchor_size));
                if (anchor_size > MAX_SHIELDED_SPEND_ANCHOR_SIZE) {
                    throw std::ios_base::failure("ShieldedNote::Unserialize oversized spend_anchor");
                }
                obj.spend_anchor.resize(anchor_size);
                if (anchor_size > 0) {
                    s.read(AsWritableBytes(Span<unsigned char>{obj.spend_anchor.data(), obj.spend_anchor.size()}));
                }
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
            // Append the spend_anchor only for marked (modern) notes; legacy notes
            // emit nothing here and stay byte-identical to the v1 wire format.
            if (UsesModernShieldedNoteDerivation(obj)) {
                const uint64_t anchor_size = obj.spend_anchor.size();
                if (anchor_size > MAX_SHIELDED_SPEND_ANCHOR_SIZE) {
                    throw std::ios_base::failure("ShieldedNote::Serialize oversized spend_anchor");
                }
                ::Serialize(s, COMPACTSIZE(anchor_size));
                if (anchor_size > 0) {
                    s.write(AsBytes(Span<const unsigned char>{obj.spend_anchor.data(), obj.spend_anchor.size()}));
                }
            }
        }
    }
};

/** Apply the modern SMILE-derivation marker to a note in-place. */
void MarkShieldedNoteForModernDerivation(ShieldedNote& note);

/** Serialize a bound-mode spend anchor (T = A*s, a mod-q PolyVec) into
 *  note.spend_anchor. This promotes the note to the v2 commitment format. The note
 *  must already carry the modern SMILE-derivation marker for the anchor to round-trip
 *  on the wire (see MarkShieldedNoteForModernDerivation). */
void SetNoteSpendAnchor(ShieldedNote& note, const shielded::lattice::PolyVec& anchor);

/** Deserialize the bound-mode spend anchor from note.spend_anchor.
 *  Returns false for a legacy/empty note or malformed anchor bytes. */
[[nodiscard]] bool GetNoteSpendAnchor(const ShieldedNote& note, shielded::lattice::PolyVec& out_anchor);

using Nullifier = uint256;

#endif // BTX_SHIELDED_NOTE_H
