// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/note.h>

#include <consensus/amount.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>

#include <algorithm>

namespace {
constexpr const char* NOTE_TAG_INNER{"BTX_Note_Inner_V1"};
constexpr const char* NOTE_TAG_COMMIT{"BTX_Note_Commit_V1"};
constexpr const char* NOTE_TAG_NULLIFIER{"BTX_Note_Nullifier_V1"};
constexpr std::array<unsigned char, 8> NOTE_MODERN_RHO_MARKER{{'S', 'M', '2', 'R', 'H', 'O', 'V', '2'}};
constexpr std::array<unsigned char, 8> NOTE_MODERN_RCM_MARKER{{'S', 'M', '2', 'R', 'C', 'M', 'V', '2'}};
} // namespace

uint256 ShieldedNote::GetCommitment() const
{
    // inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || pk_hash)
    unsigned char value_le[8];
    WriteLE64(value_le, static_cast<uint64_t>(value));

    uint256 inner;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(NOTE_TAG_INNER), sizeof("BTX_Note_Inner_V1") - 1)
        .Write(value_le, sizeof(value_le))
        .Write(recipient_pk_hash.begin(), uint256::size())
        .Finalize(inner.begin());

    // cm = SHA256("BTX_Note_Commit_V1" || inner || rho || rcm)
    uint256 cm;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(NOTE_TAG_COMMIT), sizeof("BTX_Note_Commit_V1") - 1)
        .Write(inner.begin(), uint256::size())
        .Write(rho.begin(), uint256::size())
        .Write(rcm.begin(), uint256::size())
        .Finalize(cm.begin());

    return cm;
}

uint256 ShieldedNote::GetNullifier(Span<const unsigned char> spending_key) const
{
    const uint256 cm{GetCommitment()};

    uint256 nf;
    // Use an explicit hasher so we can cleanse internal state after processing
    // spending key material (defense-in-depth against stack residue).
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(NOTE_TAG_NULLIFIER), sizeof("BTX_Note_Nullifier_V1") - 1)
          .Write(spending_key.data(), spending_key.size())
          .Write(rho.begin(), uint256::size())
          .Write(cm.begin(), uint256::size())
          .Finalize(nf.begin());
    memory_cleanse(&hasher, sizeof(hasher));
    return nf;
}

bool ShieldedNote::IsValid() const
{
    if (!MoneyRange(value)) return false;
    if (recipient_pk_hash.IsNull()) return false;
    if (rho.IsNull()) return false;
    if (rcm.IsNull()) return false;
    if (memo.size() > MAX_SHIELDED_MEMO_SIZE) return false;
    return true;
}

bool UsesModernShieldedNoteDerivation(const ShieldedNote& note)
{
    return std::equal(NOTE_MODERN_RHO_MARKER.begin(), NOTE_MODERN_RHO_MARKER.end(), note.rho.begin()) &&
           std::equal(NOTE_MODERN_RCM_MARKER.begin(), NOTE_MODERN_RCM_MARKER.end(), note.rcm.begin());
}

void MarkShieldedNoteForModernDerivation(ShieldedNote& note)
{
    std::copy(NOTE_MODERN_RHO_MARKER.begin(), NOTE_MODERN_RHO_MARKER.end(), note.rho.begin());
    std::copy(NOTE_MODERN_RCM_MARKER.begin(), NOTE_MODERN_RCM_MARKER.end(), note.rcm.begin());
}
