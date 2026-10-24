// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODISPUTE2_H
#define BTX_MODELNET_SWARM_NOTNODISPUTE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one dispute. want_settle asks this note to settle
 * that dispute.
 *
 * A dispute note settles no outpoint. settled and spent stay false on
 * every path.
 */
struct SwarmNotNoDispute2 {
    std::string dispute_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a dispute. settled and spent stay false on every
 * path. A dispute note settles no outpoint.
 */
struct SwarmNotNoDispute2Result {
    std::string code;
    bool settled{false};
    bool spent{false};
};

/**
 * Note a dispute without settling it or spending an outpoint.
 * Order, first match wins: an empty dispute_id is DISPUTE. want_settle is
 * HELD. Otherwise the note is NOTED and err is clear.
 * settled and spent stay false on every path.
 * A dispute note settles no outpoint.
 */
SwarmNotNoDispute2Result SwarmNoteNotNoDispute2(const SwarmNotNoDispute2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODISPUTE2_H
