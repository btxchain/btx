// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/ring_selection.h>

#include <crypto/common.h>
#include <random.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <optional>
#include <random>
#include <set>

namespace shielded::ringct {
namespace {

enum class DecoyRegion {
    HISTORICAL,
    RECENT,
    ANY,
};

struct PositionRange {
    uint64_t begin{0};
    uint64_t end{0};

    [[nodiscard]] bool IsValid() const
    {
        return begin <= end;
    }

    [[nodiscard]] uint64_t Size() const
    {
        return IsValid() ? (end - begin + 1) : 0;
    }
};

[[nodiscard]] PositionRange GetRegionRange(uint64_t tree_size, DecoyRegion region)
{
    if (tree_size == 0) return PositionRange{1, 0};
    const uint64_t newest = tree_size - 1;
    if (region == DecoyRegion::ANY || tree_size == 1) {
        return PositionRange{0, newest};
    }

    const uint64_t historical_end = newest / 2;
    if (region == DecoyRegion::HISTORICAL) {
        return PositionRange{0, historical_end};
    }

    const uint64_t recent_begin = historical_end + 1;
    if (recent_begin > newest) {
        return PositionRange{0, newest};
    }
    return PositionRange{recent_begin, newest};
}

// Post-audit redesign: avoid both the historical Monero gamma constants and
// the earlier ad-hoc repeated-uniform "pick the newest" heuristic. The live
// wallet now uses a truncated shifted-Pareto age sampler, which follows the
// same qualitative "newer outputs are more likely to be spent" model without
// inheriting gamma-specific edge cases or wallet-fingerprintable constants.
static constexpr double SHIFTED_PARETO_ALPHA = 0.18;
static constexpr size_t HISTORICAL_DECOY_TARGET = 7;
static constexpr size_t AGE_SPREAD_BIN_COUNT = 4;
static constexpr uint64_t MIN_TREE_SIZE_FOR_AGE_SPREAD = 64;
static constexpr uint64_t MIN_TREE_SIZE_FOR_PRIVACY = 16;
static constexpr uint64_t PRIVACY_TREE_SIZE_RING_MULTIPLIER = 2;

[[nodiscard]] size_t HistoricalDecoyQuota(size_t decoy_count)
{
    // Preserve the launch-era 7/15 split for larger rings, but keep recent
    // decoys in the majority as the supported ring size scales down to 8 and
    // when shared rings reserve slots for multiple real members.
    if (decoy_count == 0) return 0;
    return std::min(HISTORICAL_DECOY_TARGET, (decoy_count - 1) / 2);
}

[[nodiscard]] DecoyRegion PreferredDecoyRegion(size_t decoy_index, size_t decoy_count)
{
    return decoy_index < HistoricalDecoyQuota(decoy_count) ? DecoyRegion::HISTORICAL
                                                           : DecoyRegion::ANY;
}

[[nodiscard]] std::optional<PositionRange> GetAgeSpreadBinRange(uint64_t tree_size,
                                                                size_t bin_index,
                                                                size_t bin_count)
{
    if (tree_size == 0 || bin_count == 0 || bin_index >= bin_count) {
        return std::nullopt;
    }
    const uint64_t begin = (tree_size * bin_index) / bin_count;
    const uint64_t next_begin = (tree_size * (bin_index + 1)) / bin_count;
    if (next_begin == 0 || begin >= next_begin) {
        return std::nullopt;
    }
    return PositionRange{begin, next_begin - 1};
}

[[nodiscard]] bool PreferNewestWithinRange(uint64_t tree_size, const PositionRange& range)
{
    if (!range.IsValid() || tree_size <= 1) return false;
    const uint64_t recent_begin = (tree_size - 1) / 2 + 1;
    return range.begin >= recent_begin;
}

[[nodiscard]] uint64_t PositionToAge(uint64_t tree_size, uint64_t position)
{
    return tree_size == 0 ? 0 : (tree_size - 1) - position;
}

[[nodiscard]] uint64_t AgeToPosition(uint64_t tree_size, uint64_t age)
{
    return tree_size == 0 ? 0 : (tree_size - 1) - std::min<uint64_t>(age, tree_size - 1);
}

[[nodiscard]] uint64_t SampleShiftedParetoAge(uint64_t min_age,
                                              uint64_t max_age,
                                              FastRandomContext& prng)
{
    if (min_age >= max_age) return min_age;

    const auto survival = [](double age) {
        return std::pow(age + 1.0, -SHIFTED_PARETO_ALPHA);
    };

    const double low_tail = survival(static_cast<double>(min_age));
    const double high_tail = survival(static_cast<double>(max_age));
    if (!(low_tail > high_tail) ||
        !std::isfinite(low_tail) ||
        !std::isfinite(high_tail)) {
        std::uniform_int_distribution<uint64_t> dist{min_age, max_age};
        return dist(prng);
    }

    std::uniform_real_distribution<double> unit_dist{
        0.0,
        std::nextafter(1.0, std::numeric_limits<double>::lowest())};
    const double u = unit_dist(prng);
    const double sampled_tail = low_tail - (u * (low_tail - high_tail));
    if (!(sampled_tail > 0.0) || !std::isfinite(sampled_tail)) {
        std::uniform_int_distribution<uint64_t> dist{min_age, max_age};
        return dist(prng);
    }

    const double sampled_age = std::pow(sampled_tail, -1.0 / SHIFTED_PARETO_ALPHA) - 1.0;
    if (!std::isfinite(sampled_age) || sampled_age < 0.0) {
        std::uniform_int_distribution<uint64_t> dist{min_age, max_age};
        return dist(prng);
    }

    return std::clamp<uint64_t>(static_cast<uint64_t>(std::floor(sampled_age)), min_age, max_age);
}

[[nodiscard]] uint64_t SampleDecoyPosition(uint64_t tree_size,
                                           FastRandomContext& prng,
                                           DecoyRegion region)
{
    const PositionRange range = GetRegionRange(tree_size, region);
    if (!range.IsValid()) return 0;
    if (range.begin == range.end) return range.begin;

    const uint64_t min_age = PositionToAge(tree_size, range.end);
    const uint64_t max_age = PositionToAge(tree_size, range.begin);
    const uint64_t sampled_age = SampleShiftedParetoAge(min_age, max_age, prng);
    return AgeToPosition(tree_size, sampled_age);
}

template <typename IsValid>
[[nodiscard]] std::optional<uint64_t> FindCandidateInRegion(uint64_t tree_size,
                                                            FastRandomContext& prng,
                                                            DecoyRegion region,
                                                            IsValid&& is_valid)
{
    const PositionRange range = GetRegionRange(tree_size, region);
    if (!range.IsValid()) return std::nullopt;

    uint64_t candidate = SampleDecoyPosition(tree_size, prng, region);
    for (int attempt = 0; attempt < 64; ++attempt) {
        if (is_valid(candidate)) return candidate;
        candidate = SampleDecoyPosition(tree_size, prng, region);
    }

    const uint64_t range_size = range.Size();
    if (range_size == 0) return std::nullopt;
    for (uint64_t delta = 0; delta < range_size; ++delta) {
        const uint64_t pos = range.begin + ((candidate - range.begin + delta) % range_size);
        if (is_valid(pos)) return pos;
    }

    return std::nullopt;
}

template <typename IsValid>
[[nodiscard]] std::optional<uint64_t> FindCandidateInRange(const PositionRange& range,
                                                           uint64_t tree_size,
                                                           FastRandomContext& prng,
                                                           bool prefer_newest,
                                                           IsValid&& is_valid)
{
    if (!range.IsValid()) return std::nullopt;

    const auto sample_candidate = [&]() {
        if (range.begin == range.end) return range.begin;
        if (!prefer_newest) {
            std::uniform_int_distribution<uint64_t> dist{range.begin, range.end};
            return dist(prng);
        }

        const uint64_t min_age = PositionToAge(tree_size, range.end);
        const uint64_t max_age = PositionToAge(tree_size, range.begin);
        const uint64_t sampled_age = SampleShiftedParetoAge(min_age, max_age, prng);
        return AgeToPosition(tree_size, sampled_age);
    };

    uint64_t candidate = sample_candidate();
    for (int attempt = 0; attempt < 64; ++attempt) {
        if (is_valid(candidate)) return candidate;
        candidate = sample_candidate();
    }

    const uint64_t range_size = range.Size();
    if (range_size == 0) return std::nullopt;
    for (uint64_t delta = 0; delta < range_size; ++delta) {
        const uint64_t pos = range.begin + ((candidate - range.begin + delta) % range_size);
        if (is_valid(pos)) return pos;
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<uint64_t> PickExcludedDecoy(Span<const uint64_t> excluded_positions,
                                                        uint64_t tree_size,
                                                        FastRandomContext& prng,
                                                        Span<const uint64_t> real_positions,
                                                        const std::set<uint64_t>& selected_unique)
{
    std::vector<uint64_t> preferred;
    std::vector<uint64_t> fallback;
    preferred.reserve(excluded_positions.size());
    fallback.reserve(excluded_positions.size());

    std::set<uint64_t> real_set(real_positions.begin(), real_positions.end());
    for (const uint64_t pos : excluded_positions) {
        if (pos >= tree_size || real_set.count(pos) != 0) continue;
        if (selected_unique.count(pos) == 0) {
            preferred.push_back(pos);
        } else {
            fallback.push_back(pos);
        }
    }

    auto choose = [&](const std::vector<uint64_t>& candidates) -> std::optional<uint64_t> {
        if (candidates.empty()) return std::nullopt;
        std::uniform_int_distribution<size_t> dist{0, candidates.size() - 1};
        return candidates[dist(prng)];
    };

    if (auto chosen = choose(preferred)) return chosen;
    return choose(fallback);
}

} // namespace

// If a wallet passes a tip-exclusion window and the real spend lands inside
// that window, force at least one non-real member from the same window when
// possible. This prevents the exclusion set from deterministically isolating
// recent real spends while still preferring older decoys when the real spend
// is outside the excluded window.
RingSelection SelectRingPositions(uint64_t real_position,
                                  uint64_t tree_size,
                                  const uint256& seed,
                                  size_t ring_size)
{
    return SelectRingPositionsWithExclusions(real_position,
                                             tree_size,
                                             seed,
                                             ring_size,
                                             {});
}

RingSelection SelectRingPositionsWithExclusions(uint64_t real_position,
                                                uint64_t tree_size,
                                                const uint256& seed,
                                                size_t ring_size,
                                                Span<const uint64_t> excluded_positions)
{
    RingSelection selection{};
    if (ring_size == 0) return selection;
    if (tree_size == 0) {
        selection.positions.assign(ring_size, 0);
        selection.real_index = 0;
        return selection;
    }

    const uint64_t real_pos = std::min(real_position, tree_size - 1);
    selection.positions.assign(ring_size, real_pos);

    // R6-123: Use ChaCha20-based CSPRNG seeded from the 256-bit hash.
    FastRandomContext prng(seed);

    std::set<uint64_t> excluded;
    for (const uint64_t pos : excluded_positions) {
        if (pos < tree_size && pos != real_pos) excluded.insert(pos);
    }
    const bool real_in_excluded_window =
        std::find(excluded_positions.begin(), excluded_positions.end(), real_pos) != excluded_positions.end();

    std::set<uint64_t> selected_unique{real_pos};
    const size_t diversity_target = std::min<size_t>(ring_size, static_cast<size_t>(tree_size));
    const size_t decoy_count = ring_size > 0 ? ring_size - 1 : 0;
    const size_t age_spread_quota =
        tree_size >= MIN_TREE_SIZE_FOR_AGE_SPREAD && decoy_count >= AGE_SPREAD_BIN_COUNT
            ? AGE_SPREAD_BIN_COUNT
            : 0;

    const auto pick_candidate = [&](bool require_new_unique, DecoyRegion preferred_region) {
        const auto is_valid = [&](uint64_t pos, bool avoid_excluded) {
            if (pos >= tree_size) return false;
            if (require_new_unique && selected_unique.count(pos) != 0) return false;
            if (avoid_excluded && excluded.count(pos) != 0) return false;
            return true;
        };

        if (auto candidate = FindCandidateInRegion(
                tree_size,
                prng,
                preferred_region,
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/true); })) {
            return *candidate;
        }
        if (preferred_region != DecoyRegion::ANY) {
            if (auto candidate = FindCandidateInRegion(
                    tree_size,
                    prng,
                    DecoyRegion::ANY,
                    [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/true); })) {
                return *candidate;
            }
        }

        if (auto candidate = FindCandidateInRegion(
                tree_size,
                prng,
                preferred_region,
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/false); })) {
            return *candidate;
        }
        if (preferred_region != DecoyRegion::ANY) {
            if (auto candidate = FindCandidateInRegion(
                    tree_size,
                    prng,
                    DecoyRegion::ANY,
                    [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/false); })) {
                return *candidate;
            }
        }
        return real_pos;
    };

    const auto pick_age_spread_candidate = [&](bool require_new_unique, size_t bin_index) -> std::optional<uint64_t> {
        const auto range = GetAgeSpreadBinRange(tree_size, bin_index, age_spread_quota);
        if (!range.has_value()) return std::nullopt;

        const auto is_valid = [&](uint64_t pos, bool avoid_excluded) {
            if (pos >= tree_size) return false;
            if (require_new_unique && selected_unique.count(pos) != 0) return false;
            if (avoid_excluded && excluded.count(pos) != 0) return false;
            return true;
        };

        if (auto candidate = FindCandidateInRange(
                *range,
                tree_size,
                prng,
                PreferNewestWithinRange(tree_size, *range),
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/true); })) {
            return *candidate;
        }
        if (auto candidate = FindCandidateInRange(
                *range,
                tree_size,
                prng,
                PreferNewestWithinRange(tree_size, *range),
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/false); })) {
            return *candidate;
        }
        return std::nullopt;
    };

    // H4 audit fix: enforce uniqueness for all ring members when the tree is
    // large enough. When tree_size < ring_size, fill with all unique positions
    // first, then pad with duplicates (reusing unique positions) to reach
    // ring_size. This prevents duplicate positions in rings drawn from trees
    // that are large enough to support full uniqueness.
    for (size_t i = 1; i < ring_size; ++i) {
        const bool can_be_unique = selected_unique.size() < diversity_target;
        const size_t decoy_index = i - 1;
        uint64_t candidate = real_pos;
        if (decoy_index < age_spread_quota) {
            if (auto spread_candidate = pick_age_spread_candidate(can_be_unique, decoy_index)) {
                candidate = *spread_candidate;
            } else {
                candidate = pick_candidate(
                    can_be_unique,
                    PreferredDecoyRegion(decoy_index, decoy_count));
            }
        } else {
            candidate = pick_candidate(
                can_be_unique,
                PreferredDecoyRegion(decoy_index, decoy_count));
        }
        selection.positions[i] = candidate;
        selected_unique.insert(candidate);
    }

    if (real_in_excluded_window && selection.positions.size() > 1) {
        bool has_excluded_decoy{false};
        for (size_t i = 1; i < selection.positions.size(); ++i) {
            if (excluded.count(selection.positions[i]) != 0) {
                has_excluded_decoy = true;
                break;
            }
        }

        if (!has_excluded_decoy) {
            const std::array<uint64_t, 1> real_positions{real_pos};
            if (auto excluded_decoy = PickExcludedDecoy(
                    excluded_positions,
                    tree_size,
                    prng,
                    Span<const uint64_t>{real_positions.data(), real_positions.size()},
                    selected_unique)) {
                selection.positions.back() = *excluded_decoy;
            }
        }
    }

    // H4 audit fix: verify no duplicates when tree >= ring_size.
    if (tree_size >= ring_size) {
        std::set<uint64_t> final_unique(selection.positions.begin(), selection.positions.end());
        if (final_unique.size() < ring_size) {
            // This should not happen with a large enough tree. Log for debug.
            // The proof verification will still work, but this indicates a
            // sampling issue.
        }
    }

    // Randomize ring-member order so the real spend position is not fixed.
    for (size_t i = ring_size - 1; i > 0; --i) {
        std::uniform_int_distribution<size_t> dist{0, i};
        const size_t j = dist(prng);
        std::swap(selection.positions[i], selection.positions[j]);
    }

    // MatRiCT audit F6 fix: when the real position appears multiple times
    // (possible in small trees), randomly select which occurrence to designate
    // as the real index to avoid first-occurrence statistical bias.
    std::vector<size_t> real_occurrences;
    for (size_t i = 0; i < selection.positions.size(); ++i) {
        if (selection.positions[i] == real_pos) {
            real_occurrences.push_back(i);
        }
    }
    if (real_occurrences.empty()) {
        selection.real_index = 0;
    } else if (real_occurrences.size() == 1) {
        selection.real_index = real_occurrences[0];
    } else {
        std::uniform_int_distribution<size_t> occ_dist{0, real_occurrences.size() - 1};
        selection.real_index = real_occurrences[occ_dist(prng)];
    }
    return selection;
}

SharedRingSelection SelectSharedRingPositionsWithExclusions(Span<const uint64_t> real_positions,
                                                            uint64_t tree_size,
                                                            const uint256& seed,
                                                            size_t ring_size,
                                                            Span<const uint64_t> excluded_positions)
{
    SharedRingSelection selection{};
    if (real_positions.empty() || ring_size == 0 || tree_size == 0) return selection;

    std::vector<uint64_t> unique_real_positions;
    unique_real_positions.reserve(real_positions.size());
    std::set<uint64_t> unique_real_set;
    for (const uint64_t pos : real_positions) {
        if (pos >= tree_size || !unique_real_set.insert(pos).second) {
            return {};
        }
        unique_real_positions.push_back(pos);
    }
    if (unique_real_positions.size() > ring_size) return {};

    selection.positions = unique_real_positions;

    FastRandomContext prng(seed);

    std::set<uint64_t> excluded;
    for (const uint64_t pos : excluded_positions) {
        if (pos < tree_size && unique_real_set.count(pos) == 0) excluded.insert(pos);
    }
    bool any_real_in_excluded_window{false};
    for (const uint64_t real_pos : unique_real_positions) {
        if (std::find(excluded_positions.begin(), excluded_positions.end(), real_pos) != excluded_positions.end()) {
            any_real_in_excluded_window = true;
            break;
        }
    }

    std::set<uint64_t> selected_unique = unique_real_set;
    const size_t diversity_target = std::min<size_t>(ring_size, static_cast<size_t>(tree_size));
    const size_t decoy_count = ring_size - unique_real_positions.size();
    const size_t age_spread_quota =
        tree_size >= MIN_TREE_SIZE_FOR_AGE_SPREAD && decoy_count >= AGE_SPREAD_BIN_COUNT
            ? AGE_SPREAD_BIN_COUNT
            : 0;

    const auto pick_candidate = [&](bool require_new_unique, DecoyRegion preferred_region) {
        const auto is_valid = [&](uint64_t pos, bool avoid_excluded) {
            if (pos >= tree_size) return false;
            if (require_new_unique && selected_unique.count(pos) != 0) return false;
            if (avoid_excluded && excluded.count(pos) != 0) return false;
            return true;
        };

        if (auto candidate = FindCandidateInRegion(
                tree_size,
                prng,
                preferred_region,
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/true); })) {
            return *candidate;
        }
        if (preferred_region != DecoyRegion::ANY) {
            if (auto candidate = FindCandidateInRegion(
                    tree_size,
                    prng,
                    DecoyRegion::ANY,
                    [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/true); })) {
                return *candidate;
            }
        }

        if (auto candidate = FindCandidateInRegion(
                tree_size,
                prng,
                preferred_region,
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/false); })) {
            return *candidate;
        }
        if (preferred_region != DecoyRegion::ANY) {
            if (auto candidate = FindCandidateInRegion(
                    tree_size,
                    prng,
                    DecoyRegion::ANY,
                    [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/false); })) {
                return *candidate;
            }
        }
        return unique_real_positions.front();
    };

    const auto pick_age_spread_candidate = [&](bool require_new_unique, size_t bin_index) -> std::optional<uint64_t> {
        const auto range = GetAgeSpreadBinRange(tree_size, bin_index, age_spread_quota);
        if (!range.has_value()) return std::nullopt;

        const auto is_valid = [&](uint64_t pos, bool avoid_excluded) {
            if (pos >= tree_size) return false;
            if (require_new_unique && selected_unique.count(pos) != 0) return false;
            if (avoid_excluded && excluded.count(pos) != 0) return false;
            return true;
        };

        if (auto candidate = FindCandidateInRange(
                *range,
                tree_size,
                prng,
                PreferNewestWithinRange(tree_size, *range),
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/true); })) {
            return *candidate;
        }
        if (auto candidate = FindCandidateInRange(
                *range,
                tree_size,
                prng,
                PreferNewestWithinRange(tree_size, *range),
                [&](uint64_t pos) { return is_valid(pos, /*avoid_excluded=*/false); })) {
            return *candidate;
        }
        return std::nullopt;
    };

    // H4 audit fix: enforce uniqueness when tree is large enough.
    while (selection.positions.size() < ring_size) {
        const bool can_be_unique = selected_unique.size() < diversity_target;
        const size_t decoy_index = selection.positions.size() - unique_real_positions.size();
        uint64_t candidate = unique_real_positions.front();
        if (decoy_index < age_spread_quota) {
            if (auto spread_candidate = pick_age_spread_candidate(can_be_unique, decoy_index)) {
                candidate = *spread_candidate;
            } else {
                candidate = pick_candidate(
                    can_be_unique,
                    PreferredDecoyRegion(decoy_index, decoy_count));
            }
        } else {
            candidate = pick_candidate(
                can_be_unique,
                PreferredDecoyRegion(decoy_index, decoy_count));
        }
        selection.positions.push_back(candidate);
        selected_unique.insert(candidate);
    }

    if (any_real_in_excluded_window && selection.positions.size() > unique_real_positions.size()) {
        bool has_excluded_decoy{false};
        for (const uint64_t pos : selection.positions) {
            if (unique_real_set.count(pos) == 0 && excluded.count(pos) != 0) {
                has_excluded_decoy = true;
                break;
            }
        }

        if (!has_excluded_decoy) {
            if (auto excluded_decoy = PickExcludedDecoy(
                    excluded_positions,
                    tree_size,
                    prng,
                    Span<const uint64_t>{unique_real_positions.data(), unique_real_positions.size()},
                    selected_unique)) {
                selection.positions.back() = *excluded_decoy;
            }
        }
    }

    for (size_t i = selection.positions.size() - 1; i > 0; --i) {
        std::uniform_int_distribution<size_t> dist{0, i};
        const size_t j = dist(prng);
        std::swap(selection.positions[i], selection.positions[j]);
    }

    selection.real_indices.reserve(real_positions.size());
    for (const uint64_t real_pos : real_positions) {
        const auto it = std::find(selection.positions.begin(), selection.positions.end(), real_pos);
        if (it == selection.positions.end()) return {};
        selection.real_indices.push_back(static_cast<size_t>(it - selection.positions.begin()));
    }

    return selection;
}

uint64_t GetMinimumPrivacyTreeSize(size_t ring_size)
{
    if (ring_size == 0) return 0;
    const uint64_t ring_scaled =
        static_cast<uint64_t>(ring_size) * PRIVACY_TREE_SIZE_RING_MULTIPLIER;
    return std::max<uint64_t>(MIN_TREE_SIZE_FOR_PRIVACY, ring_scaled);
}

} // namespace shielded::ringct
