// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_coins.h>

#include <consensus/amount.h>

#include <algorithm>
#include <numeric>

namespace wallet {
namespace {

static constexpr int BNB_MAX_ITERATIONS{100000};

[[nodiscard]] CAmount CostOfChange(CAmount fee_per_weight)
{
    if (fee_per_weight < 0) return 0;
    static constexpr CAmount kMaxSafe = std::numeric_limits<CAmount>::max() / static_cast<CAmount>(SHIELDED_OUTPUT_SIZE);
    if (fee_per_weight > kMaxSafe) return std::numeric_limits<CAmount>::max();
    return fee_per_weight * static_cast<CAmount>(SHIELDED_OUTPUT_SIZE);
}

/** Saturating addition for CAmount to prevent overflow in coin selection. */
[[nodiscard]] CAmount SaturatingAdd(CAmount a, CAmount b)
{
    if (b > 0 && a > std::numeric_limits<CAmount>::max() - b) return std::numeric_limits<CAmount>::max();
    if (b < 0 && a < std::numeric_limits<CAmount>::min() - b) return std::numeric_limits<CAmount>::min();
    return a + b;
}

[[nodiscard]] bool BnBSearch(const std::vector<ShieldedCoin>& available,
                             CAmount target,
                             CAmount cost_of_change,
                             CAmount fee_per_weight,
                             std::vector<bool>& selection,
                             CAmount current_value,
                             size_t depth,
                             int& iterations)
{
    if (current_value > SaturatingAdd(target, cost_of_change)) return false;
    if (current_value >= target) return true;
    if (++iterations > BNB_MAX_ITERATIONS) return false;
    if (depth >= available.size()) return false;

    selection[depth] = true;
    if (BnBSearch(available,
                  target,
                  cost_of_change,
                  fee_per_weight,
                  selection,
                  SaturatingAdd(current_value, available[depth].EffectiveValue(fee_per_weight)),
                  depth + 1,
                  iterations)) {
        return true;
    }

    selection[depth] = false;
    return BnBSearch(available,
                     target,
                     cost_of_change,
                     fee_per_weight,
                     selection,
                     current_value,
                     depth + 1,
                     iterations);
}

} // namespace

std::vector<ShieldedCoin> ShieldedCoinSelection(const std::vector<ShieldedCoin>& available,
                                                CAmount target,
                                                CAmount fee_per_weight)
{
    if (available.empty() || target <= 0) return {};

    const CAmount total_available = std::accumulate(available.begin(),
                                                    available.end(),
                                                    CAmount{0},
                                                    [](CAmount sum, const ShieldedCoin& c) {
                                                        return SaturatingAdd(sum, c.note.value);
                                                    });
    if (total_available < target) return {};

    std::vector<ShieldedCoin> effective_candidates = available;
    std::sort(effective_candidates.begin(), effective_candidates.end(), [fee_per_weight](const ShieldedCoin& a, const ShieldedCoin& b) {
        return a.EffectiveValue(fee_per_weight) > b.EffectiveValue(fee_per_weight);
    });

    effective_candidates.erase(std::remove_if(effective_candidates.begin(), effective_candidates.end(), [fee_per_weight](const ShieldedCoin& c) {
                                  return c.EffectiveValue(fee_per_weight) <= 0;
                              }),
                              effective_candidates.end());

    if (!effective_candidates.empty()) {
        const CAmount total_effective = std::accumulate(effective_candidates.begin(),
                                                        effective_candidates.end(),
                                                        CAmount{0},
                                                        [fee_per_weight](CAmount sum, const ShieldedCoin& c) {
                                                            return SaturatingAdd(sum, c.EffectiveValue(fee_per_weight));
                                                        });

        if (total_effective >= target) {
            const CAmount change_cost = CostOfChange(fee_per_weight);
            std::vector<bool> selection(effective_candidates.size(), false);
            int iterations{0};
            if (BnBSearch(effective_candidates,
                          target,
                          change_cost,
                          fee_per_weight,
                          selection,
                          /*current_value=*/0,
                          /*depth=*/0,
                          iterations)) {
                std::vector<ShieldedCoin> out;
                out.reserve(effective_candidates.size());
                for (size_t i = 0; i < effective_candidates.size(); ++i) {
                    if (selection[i]) out.push_back(effective_candidates[i]);
                }
                return out;
            }
        }
    }

    return ShieldedKnapsackSolver(available, target);
}

std::vector<ShieldedCoin> ShieldedKnapsackSolver(const std::vector<ShieldedCoin>& available,
                                                 CAmount target)
{
    if (available.empty() || target <= 0) return {};

    std::vector<ShieldedCoin> sorted = available;
    std::sort(sorted.begin(), sorted.end(), [](const ShieldedCoin& a, const ShieldedCoin& b) {
        return a.note.value > b.note.value;
    });

    std::vector<ShieldedCoin> out;
    CAmount running{0};
    for (const auto& coin : sorted) {
        if (running >= target) break;
        out.push_back(coin);
        running = SaturatingAdd(running, coin.note.value);
    }
    if (running < target) return {};

    for (const auto& coin : sorted) {
        if (coin.note.value >= target && coin.note.value < running) {
            return {coin};
        }
    }
    return out;
}

std::vector<ShieldedCoin> GetDustNotes(const std::vector<ShieldedCoin>& notes,
                                       CAmount dust_threshold)
{
    std::vector<ShieldedCoin> out;
    out.reserve(notes.size());
    for (const auto& coin : notes) {
        if (!coin.is_spent && coin.note.value < dust_threshold) {
            out.push_back(coin);
        }
    }
    return out;
}

} // namespace wallet
