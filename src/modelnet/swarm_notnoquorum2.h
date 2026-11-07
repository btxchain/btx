// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUORUM2_H
#define BTX_MODELNET_SWARM_NOTNOQUORUM2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one quorum. same_evaluator and same_domain record
 * whether evaluators or trust domains are shared. want_settle asks this
 * note to settle.
 *
 * A quorum needs distinct evaluators and distinct trust domains. This
 * note settles nothing. settled stays false and atoms stays 0 on every
 * path.
 */
struct SwarmNotNoQuorum2 {
    std::string quorum_id;
    bool same_evaluator{false};
    bool same_domain{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a quorum. settled stays false and atoms stays 0 on
 * every path. A quorum needs distinct evaluators and distinct trust
 * domains. This note settles nothing.
 */
struct SwarmNotNoQuorum2Result {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note a quorum without settling it. Order, first match wins: an empty
 * quorum_id is QUORUM. same_evaluator or same_domain true is NOT_SETTLED,
 * even when want_settle is false. want_settle is HELD. Otherwise the note
 * is NOTED and err is cleared. settled stays false and atoms stays 0 on
 * every path. A quorum needs distinct evaluators and distinct trust
 * domains.
 */
SwarmNotNoQuorum2Result SwarmNoteNotNoQuorum2(const SwarmNotNoQuorum2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUORUM2_H
