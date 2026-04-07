// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/turnstile.h>

#include <consensus/amount.h>
#include <logging.h>
#include <util/overflow.h>

bool ShieldedPoolBalance::ApplyValueBalance(CAmount value_balance)
{
    if (!MoneyRangeSigned(value_balance)) {
        return false;
    }
    // R6-411: Use CheckedAdd with negation to prevent signed integer overflow (UB).
    // Note: negating INT64_MIN is UB, but MoneyRangeSigned above rejects it.
    const auto new_balance = CheckedAdd(m_balance, -value_balance);
    if (!new_balance || !MoneyRange(*new_balance) || *new_balance < 0) {
        LogPrintf("ShieldedPoolBalance::ApplyValueBalance rejected invalid balance transition (%lld)\n",
                  m_balance);
        return false;
    }
    m_balance = *new_balance;
    return true;
}

bool ShieldedPoolBalance::UndoValueBalance(CAmount value_balance)
{
    if (!MoneyRangeSigned(value_balance)) {
        return false;
    }
    // R6-411: Use CheckedAdd to prevent signed integer overflow (UB).
    const auto new_balance = CheckedAdd(m_balance, value_balance);
    if (!new_balance || !MoneyRange(*new_balance) || *new_balance < 0) {
        LogPrintf("ShieldedPoolBalance::UndoValueBalance rejected invalid balance transition (%lld)\n",
                  m_balance);
        return false;
    }
    m_balance = *new_balance;
    return true;
}

bool ShieldedPoolBalance::SetBalance(CAmount balance)
{
    if (!MoneyRange(balance) || balance < 0) {
        return false;
    }
    m_balance = balance;
    return true;
}
