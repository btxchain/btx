// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_SHIELDED_COINS_H
#define BITCOIN_WALLET_SHIELDED_COINS_H

#include <consensus/amount.h>
#include <shielded/account_registry.h>
#include <shielded/note.h>
#include <shielded/v2_types.h>
#include <uint256.h>

#include <cstddef>
#include <optional>
#include <type_traits>
#include <vector>

namespace wallet {

/** Size estimate for one shielded spend element. */
static constexpr size_t SHIELDED_SPEND_INPUT_SIZE{2613};
/** Size estimate for one shielded output element. */
static constexpr size_t SHIELDED_OUTPUT_SIZE{1213};

/** Wallet-owned shielded note metadata. */
struct ShieldedCoin
{
    ShieldedNote note;
    shielded::v2::NoteClass note_class{shielded::v2::NoteClass::USER};
    uint256 commitment;
    Nullifier nullifier;
    uint64_t tree_position{0};
    int confirmation_height{-1};
    int spent_height{-1};
    bool is_spent{false};
    bool is_mine_spend{false};
    uint256 block_hash;
    std::optional<shielded::registry::AccountLeafHint> account_leaf_hint;

    SERIALIZE_METHODS(ShieldedCoin, obj)
    {
        READWRITE(obj.note,
                  obj.commitment,
                  obj.nullifier,
                  obj.tree_position,
                  obj.confirmation_height,
                  obj.spent_height,
                  obj.is_spent,
                  obj.is_mine_spend,
                  obj.block_hash);
        bool has_account_leaf_hint = obj.account_leaf_hint.has_value();
        READWRITE(has_account_leaf_hint);
        if (has_account_leaf_hint) {
            if constexpr (std::is_same_v<decltype(ser_action), ActionSerialize>) {
                READWRITE(*obj.account_leaf_hint);
            } else {
                obj.account_leaf_hint.emplace();
                READWRITE(*obj.account_leaf_hint);
            }
        } else if constexpr (!std::is_same_v<decltype(ser_action), ActionSerialize>) {
            obj.account_leaf_hint.reset();
        }
    }

    /** Return the note's effective value under a given fee-per-weight estimate.
     *  Returns 0 if the spend cost exceeds the note value or on overflow. */
    CAmount EffectiveValue(CAmount fee_per_weight) const
    {
        if (fee_per_weight < 0) return 0;
        // Guard against multiplication overflow: SHIELDED_SPEND_INPUT_SIZE is
        // small (2613), so overflow only happens with pathological fee_per_weight.
        static constexpr CAmount kMaxSafeFeePerWeight = std::numeric_limits<CAmount>::max() / static_cast<CAmount>(SHIELDED_SPEND_INPUT_SIZE);
        if (fee_per_weight > kMaxSafeFeePerWeight) return 0;
        const CAmount spend_cost = fee_per_weight * static_cast<CAmount>(SHIELDED_SPEND_INPUT_SIZE);
        if (note.value <= spend_cost) return 0;
        return note.value - spend_cost;
    }

    /** Return depth at the provided tip height. */
    int GetDepth(int tip_height) const
    {
        if (confirmation_height < 0) return 0;
        return tip_height - confirmation_height + 1;
    }
};

/** Branch-and-bound + knapsack fallback note selection. */
std::vector<ShieldedCoin> ShieldedCoinSelection(const std::vector<ShieldedCoin>& available,
                                                CAmount target,
                                                CAmount fee_per_weight);

/** Greedy knapsack fallback note selection. */
std::vector<ShieldedCoin> ShieldedKnapsackSolver(const std::vector<ShieldedCoin>& available,
                                                 CAmount target);

/** Return currently unspent notes below `dust_threshold`. */
std::vector<ShieldedCoin> GetDustNotes(const std::vector<ShieldedCoin>& notes,
                                       CAmount dust_threshold);

} // namespace wallet

#endif // BITCOIN_WALLET_SHIELDED_COINS_H
