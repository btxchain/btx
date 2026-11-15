// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOORD_H
#define BTX_MODELNET_SWARM_NOTNOCOORD_H

#include <string>

namespace modelnet {

/**
 * A local note about one node and its coordinator. coordinator_on is the
 * coordinator flag. want_skip asks this note to skip the join.
 *
 * Turning a coordinator off does not skip join, so skipped and joined
 * stay false on every path.
 */
struct SwarmNotNoCoord {
    std::string node_id;
    bool coordinator_on{false};
    bool want_skip{false};
};

/**
 * Outcome of noting a coordinator. skipped and joined stay false on every
 * path: turning a coordinator off does not skip join.
 */
struct SwarmNotNoCoordResult {
    std::string code;
    bool skipped{false};
    bool joined{false};
};

/**
 * Note a coordinator without skipping the join. Order, first match wins:
 * an empty node_id is NODE. If coordinator_on is false, the note is HELD
 * even when want_skip is false. want_skip is HELD. Otherwise the note is
 * NOTED and err is cleared. skipped and joined stay false on every path.
 * Turning a coordinator off does not skip join.
 */
SwarmNotNoCoordResult SwarmNoteNotNoCoord(const SwarmNotNoCoord& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOORD_H
