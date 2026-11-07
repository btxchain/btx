// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAVGWEIGHT2_H
#define BTX_MODELNET_SWARM_NOTNOAVGWEIGHT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_average asks this note to average
 * weights for island admission.
 *
 * Island admission averages no weights. averaged and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoAvgWeight2 {
    std::string run_id;
    bool want_average{false};
};

/**
 * Outcome of noting an island-admission average request. averaged and
 * bytes_moved stay false on every path. Island admission averages no
 * weights.
 */
struct SwarmNotNoAvgWeight2Result {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note an island-admission average request without averaging weights or
 * moving bytes. Order, first match wins: an empty run_id is RUN.
 * want_average is HELD. Otherwise the note is NOTED and err is cleared.
 * averaged and bytes_moved stay false on every path. Island admission
 * averages no weights.
 */
SwarmNotNoAvgWeight2Result SwarmNoteNotNoAvgWeight2(const SwarmNotNoAvgWeight2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAVGWEIGHT2_H
