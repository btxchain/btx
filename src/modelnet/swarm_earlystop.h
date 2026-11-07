// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EARLYSTOP_H
#define BTX_MODELNET_SWARM_EARLYSTOP_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory early-stop gate for one experiment budget. Open stores a
 * positive remainder. Each Step spends one unit and keeps the latest
 * score. A score lower than the previous score stops the run: the
 * remainder becomes zero and the run is not promoted. A run that never
 * stepped is not promoted. A run whose scores did not fall can be
 * promoted, including after the budget is spent.
 *
 * Stopped runs stay stored. This gate does not broadcast, spend, spawn
 * a child process, open a network connection, or record a hostname or
 * address.
 */
class SwarmEarlyStop {
public:
    /**
     * An empty experiment is EXPERIMENT. budget < 1 is BUDGET. A second
     * Open for the same experiment is REPLAY and leaves the stored row.
     * Success stores remaining = budget and clears err.
     */
    bool Open(const std::string& experiment, int64_t budget, std::string& err);

    /**
     * An unknown experiment is EXPERIMENT. A remainder of zero is STOPPED
     * and leaves the stored score. score_ppm < 0 is RANGE and leaves the
     * row. Otherwise the remainder drops by one, the latest score is
     * stored, and the call returns true. When that score is lower than
     * the previous score, the run is marked early-stopped and the
     * remainder is set to zero.
     */
    bool Step(const std::string& experiment, int64_t score_ppm, std::string& err);

    /**
     * An unknown experiment is EXPERIMENT. An early-stopped run is
     * STOPPED and the row is left in place. A run that has not stepped
     * is STEP. Otherwise the call returns true and clears err.
     */
    bool Promote(const std::string& experiment, std::string& err);

    /** True only when the experiment was stopped by a falling score. */
    bool stopped(const std::string& experiment) const;

    /** Stored remainder, or -1 when the experiment was never opened. */
    int64_t remaining(const std::string& experiment) const;

    /** Latest stored score, or -1 when the experiment has no score. */
    int64_t score(const std::string& experiment) const;

private:
    struct Run {
        int64_t remaining{0};
        int64_t score_ppm{0};
        bool has_score{false};
        bool early_stop{false};
    };

    std::map<std::string, Run> m_runs;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EARLYSTOP_H
