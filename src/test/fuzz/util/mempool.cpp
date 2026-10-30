// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <kernel/mempool_entry.h>
#include <primitives/transaction.h>
#include <shielded/bundle.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>
#include <utility>

namespace {
// The CTxMemPoolEntry constructor Assume()s (kernel/mempool_entry.h) that the
// transparent input value it derives, outputs + fee - shielded value balance,
// is a money amount and is not below in_chain_input_value, which is set to the
// outputs below. Return the fee range that meets both, if there is one.
std::optional<std::pair<CAmount, CAmount>> EntryFeeRange(const CTransaction& tx)
{
    const CAmount value_out{tx.GetValueOut()};
    const CAmount value_balance{tx.HasShieldedBundle() ? GetShieldedTxValueBalance(tx.GetShieldedBundle()) : CAmount{0}};
    if (!MoneyRange(value_out) || !MoneyRangeSigned(value_balance)) return std::nullopt;
    // Avoid:
    // policy/feerate.cpp:28:34: runtime error: signed integer overflow: 34873208148477500 * 1000 cannot be represented in type 'long'
    //
    // Reproduce using CFeeRate(348732081484775, 10).GetFeePerK()
    const CAmount fee_cap{std::min<CAmount>(MAX_MONEY, std::numeric_limits<CAmount>::max() / CAmount{100'000})};
    const CAmount lo{std::max<CAmount>(0, value_balance)};
    const CAmount hi{std::min<CAmount>(fee_cap, MAX_MONEY - value_out + value_balance)};
    if (lo > hi) return std::nullopt;
    return std::make_pair(lo, hi);
}
} // namespace

bool SanityCheckForConsumeTxMemPoolEntry(const CTransaction& tx) noexcept
{
    try {
        return EntryFeeRange(tx).has_value();
    } catch (const std::exception&) {
        return false;
    }
}

// NOTE: Transaction must pass SanityCheckForConsumeTxMemPoolEntry first
CTxMemPoolEntry ConsumeTxMemPoolEntry(FuzzedDataProvider& fuzzed_data_provider, const CTransaction& tx) noexcept
{
    const auto [fee_lo, fee_hi]{*Assert(EntryFeeRange(tx))};
    const CAmount fee{fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(fee_lo, fee_hi)};
    assert(MoneyRange(fee));
    const int64_t time = fuzzed_data_provider.ConsumeIntegral<int64_t>();
    const uint64_t entry_sequence{fuzzed_data_provider.ConsumeIntegral<uint64_t>()};
    const double coin_age = fuzzed_data_provider.ConsumeFloatingPoint<double>();
    const unsigned int entry_height = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, std::numeric_limits<unsigned int>::max() - 1);
    const bool spends_coinbase = fuzzed_data_provider.ConsumeBool();
    const int32_t extra_weight = fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(0, GetTransactionWeight(tx) * 3);
    const unsigned int sig_op_cost = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, MAX_BLOCK_SIGOPS_COST);
    return CTxMemPoolEntry{MakeTransactionRef(tx), fee, time, entry_height, entry_sequence, {
        .inputs_coin_age = coin_age,
        .in_chain_input_value = tx.GetValueOut(),
    },
        /*spends_coinbase=*/ spends_coinbase,
        /*extra_weight=*/ extra_weight,
        /*sigops_cost=*/ sig_op_cost,
        /*lp=*/ {}};
}
