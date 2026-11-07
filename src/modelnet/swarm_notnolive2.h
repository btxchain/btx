// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLIVE2_H
#define BTX_MODELNET_SWARM_NOTNOLIVE2_H

#include <string>

namespace modelnet {

/**
 * A unit note about one fault. want_inject asks this note to inject a
 * live fault.
 *
 * A unit note injects no live fault. injected and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoLive2 {
    std::string fault_id;
    bool want_inject{false};
};

/**
 * Outcome of noting a fault. injected and bytes_moved stay false on
 * every path: a unit note injects no live fault.
 */
struct SwarmNotNoLive2Result {
    std::string code;
    bool injected{false};
    bool bytes_moved{false};
};

/**
 * Note a fault without injecting it.
 * Order, first match wins: an empty fault_id is FAULT.
 * want_inject is NOT_INJECTED.
 * Otherwise the note is NOTED and err is cleared.
 * injected and bytes_moved stay false on every path.
 * A unit note injects no live fault.
 */
SwarmNotNoLive2Result SwarmNoteNotNoLive2(const SwarmNotNoLive2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLIVE2_H
