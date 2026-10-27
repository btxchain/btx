// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SELFSCORE_H
#define BTX_MODELNET_SWARM_SELFSCORE_H

#include <string>

namespace modelnet {

/**
 * A local note of a requested report score.
 * report_id names the report. same_author is true when the scorer is the
 * author. want_score asks this note to score the report.
 * scored stays false on every path.
 */
struct SwarmSelfScore {
    std::string report_id;
    bool same_author{false};
    bool want_score{false};
};

/**
 * Outcome of noting a report score. scored stays false.
 */
struct SwarmSelfScoreResult {
    std::string code;
    bool scored{false};
};

/**
 * Note a report score without scoring it.
 * Order, first match wins:
 * an empty report_id is REPORT.
 * same_author is NOT_SCORED, including when want_score is false.
 * want_score is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * scored stays false on every path.
 */
SwarmSelfScoreResult SwarmNoteSelfScore(const SwarmSelfScore& report, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SELFSCORE_H
