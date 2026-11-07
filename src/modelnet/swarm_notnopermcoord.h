// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPERMCOORD_H
#define BTX_MODELNET_SWARM_NOTNOPERMCOORD_H

#include <string>

namespace modelnet {

/**
 * A local note about one coordinator. coord_id names the coordinator.
 * gone marks the coordinator as permanently lost. want_replace asks this
 * note to install a replacement.
 *
 * Permanent coordinator loss does not install a replacement and does not
 * train. Earned rows stay. replaced and trained stay false on every path.
 */
struct SwarmNotNoPermCoord {
    std::string coord_id;
    bool gone{false};
    bool want_replace{false};
};

/**
 * Outcome of noting a coordinator. replaced and trained stay false on
 * every path. Permanent coordinator loss does not install a replacement
 * and does not train. Earned rows stay.
 */
struct SwarmNotNoPermCoordResult {
    std::string code;
    bool replaced{false};
    bool trained{false};
};

/**
 * Note a coordinator without installing a replacement or training.
 * Order, first match wins: an empty coord_id is COORD. If gone is true,
 * the note is PERMANENT even when want_replace is false. want_replace is
 * HELD. Otherwise the note is NOTED and err is cleared. replaced and
 * trained stay false on every path. Permanent coordinator loss does not
 * install a replacement and does not train. Earned rows stay.
 */
SwarmNotNoPermCoordResult SwarmNoteNotNoPermCoord(const SwarmNotNoPermCoord& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPERMCOORD_H
