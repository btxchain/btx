// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_TURNSTILE_H
#define BTX_SHIELDED_TURNSTILE_H

#include <consensus/amount.h>
#include <serialize.h>

/**
 * Tracks total value currently held in the shielded pool.
 *
 * Invariant: pool balance is always in [0, MAX_MONEY].
 */
class ShieldedPoolBalance
{
public:
    /** Return the current shielded pool balance. */
    [[nodiscard]] CAmount GetBalance() const { return m_balance; }

    /**
     * Apply a transaction value balance to the pool.
     *
     * value_balance > 0 means value leaves pool (unshield).
     * value_balance < 0 means value enters pool (shield).
     */
    [[nodiscard]] bool ApplyValueBalance(CAmount value_balance);

    /** Reverse a previously applied value balance. */
    [[nodiscard]] bool UndoValueBalance(CAmount value_balance);

    /** Set balance from persisted state. */
    [[nodiscard]] bool SetBalance(CAmount balance);

    SERIALIZE_METHODS(ShieldedPoolBalance, obj)
    {
        READWRITE(obj.m_balance);
    }

private:
    CAmount m_balance{0};
};

#endif // BTX_SHIELDED_TURNSTILE_H
