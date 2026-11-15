// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOOUTPOINT_H
#define BTX_MODELNET_SWARM_NOTNOOUTPOINT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one dispute. want_settle asks this note to settle
 * that dispute.
 *
 * A dispute note settles no outpoint and pays nothing. settled stays
 * false and atoms stays 0 on every path.
 */
struct SwarmNotNoOutpoint {
    std::string dispute_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a dispute. settled stays false and atoms stays 0 on
 * every path. A dispute note settles no outpoint and pays nothing.
 */
struct SwarmNotNoOutpointResult {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note a dispute without settling an outpoint or paying atoms.
 * Order, first match wins: an empty dispute_id is DISPUTE. want_settle is
 * NOT_SETTLED. Otherwise the note is NOTED and err is cleared.
 * settled stays false and atoms stays 0 on every path.
 * A dispute note settles no outpoint and pays nothing.
 */
SwarmNotNoOutpointResult SwarmNoteNotNoOutpoint(const SwarmNotNoOutpoint& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOOUTPOINT_H
