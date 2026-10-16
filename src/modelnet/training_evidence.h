// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRAINING_EVIDENCE_H
#define BITCOIN_MODELNET_TRAINING_EVIDENCE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** One half-open training step interval joined on state commitments. */
struct Interval {
    uint64_t start_inclusive{0};
    uint64_t end_exclusive{0};
    std::string start_state;
    std::string end_state;
    std::string profile;
    std::string rng;
    std::string optimizer;
    std::string data_cursor;
    std::string ancestry;
    bool publisher_only{false};
};

/**
 * True only when a chain of usable intervals covers [0, total) from start_state
 * to final_state. Search is BFS over (position, state) from (0, start_state).
 * An interval is an edge only when start_inclusive < end_exclusive <= total and
 * its start node was already reached. A gap or a state mismatch returns false.
 */
bool FullReplayCoverage(uint64_t total,
                        const std::string& start_state,
                        const std::string& final_state,
                        const std::vector<Interval>& intervals);

/**
 * Accept one interval against a frozen EXACT_CHECKS profile.
 * Fails BTX035_PROFILE, BTX035_RNG, or BTX035_ANCESTRY.
 */
bool AcceptInterval(const Interval& interval,
                    const std::string& frozen_rng,
                    const std::string& frozen_optimizer,
                    const std::string& frozen_data_cursor,
                    std::string& err);

/** Publisher-only intervals are not independent coverage. */
bool Independent(const Interval& interval);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRAINING_EVIDENCE_H
