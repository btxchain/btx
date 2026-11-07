// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODOMAIN2_H
#define BTX_MODELNET_SWARM_NOTNODOMAIN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one quorum. distinct_evaluators and distinct_domains
 * record whether evaluators and trust domains are distinct. want_settle
 * asks this note to settle.
 *
 * A quorum needs distinct evaluators and distinct trust domains. This
 * note settles nothing. settled and bytes_moved stay false on every
 * path.
 */
struct SwarmNotNoDomain2 {
    std::string quorum_id;
    bool distinct_evaluators{false};
    bool distinct_domains{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a quorum. settled and bytes_moved stay false on
 * every path. A quorum needs distinct evaluators and distinct trust
 * domains. This note settles nothing.
 */
struct SwarmNotNoDomain2Result {
    std::string code;
    bool settled{false};
    bool bytes_moved{false};
};

/**
 * Note a quorum without settling it. Order, first match wins: an empty
 * quorum_id is QUORUM. distinct_evaluators false or distinct_domains
 * false is HELD, even when want_settle is false. want_settle is HELD.
 * Otherwise the note is NOTED and err is cleared. settled and
 * bytes_moved stay false on every path. A quorum needs distinct
 * evaluators and distinct trust domains. This note settles nothing.
 */
SwarmNotNoDomain2Result SwarmNoteNotNoDomain2(const SwarmNotNoDomain2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODOMAIN2_H
