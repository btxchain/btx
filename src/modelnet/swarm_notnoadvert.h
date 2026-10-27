// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOADVERT_H
#define BTX_MODELNET_SWARM_NOTNOADVERT_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. caller_rate is a caller-supplied token
 * rate. want_advertise asks this note to advertise the engine.
 *
 * advertised and qualified stay false on every path. A caller-supplied
 * token rate does not advertise or qualify an engine and starts nothing.
 */
struct SwarmNotNoAdvert {
    std::string engine_id;
    bool caller_rate{false};
    bool want_advertise{false};
};

/**
 * Outcome of noting an engine. advertised and qualified stay false on
 * every path. A caller-supplied token rate does not advertise or qualify
 * an engine and starts nothing.
 */
struct SwarmNotNoAdvertResult {
    std::string code;
    bool advertised{false};
    bool qualified{false};
};

/**
 * Note an engine without advertising or qualifying it. Order, first
 * match wins: an empty engine_id is ENGINE. caller_rate is UNMEASURED
 * even when want_advertise is false. want_advertise is UNMEASURED.
 * Otherwise the note is NOTED and err is clear. advertised and qualified
 * stay false on every path. A caller-supplied token rate does not
 * advertise or qualify an engine and starts nothing.
 */
SwarmNotNoAdvertResult SwarmNoteNotNoAdvert(const SwarmNotNoAdvert& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOADVERT_H
