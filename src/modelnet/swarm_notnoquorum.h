// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUORUM_H
#define BTX_MODELNET_SWARM_NOTNOQUORUM_H

#include <string>

namespace modelnet {

/**
 * A local note about one quorum. same_domain records whether the
 * evaluators share one trust domain. want_settle asks this note to settle.
 *
 * Evaluators in one trust domain do not settle. settled and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoQuorum {
    std::string report_id;
    bool same_domain{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a quorum. settled and bytes_moved stay false on every
 * path. Evaluators in one trust domain do not settle.
 */
struct SwarmNotNoQuorumResult {
    std::string code;
    bool settled{false};
    bool bytes_moved{false};
};

/**
 * Note a quorum without settling it. Order, first match wins: an empty
 * report_id is REPORT. same_domain true is SAME_DOMAIN, even when
 * want_settle is false. want_settle is HELD. Otherwise the note is NOTED
 * and err is clear. settled and bytes_moved stay false on every path.
 * Evaluators in one trust domain do not settle.
 */
SwarmNotNoQuorumResult SwarmNoteNotNoQuorum(const SwarmNotNoQuorum& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUORUM_H
