// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFAULTINJECT2_H
#define BTX_MODELNET_SWARM_NOTNOFAULTINJECT2_H

#include <string>

namespace modelnet {

/**
 * A unit note about one fault. want_inject asks this note to inject a
 * live fault.
 *
 * A unit note does not inject a live fault. injected and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoFaultInject2 {
    std::string fault_id;
    bool want_inject{false};
};

/**
 * Outcome of noting a fault. injected and bytes_moved stay false on
 * every path: a unit note does not inject a live fault.
 */
struct SwarmNotNoFaultInject2Result {
    std::string code;
    bool injected{false};
    bool bytes_moved{false};
};

/**
 * Note a fault without injecting it.
 * Order, first match wins: an empty fault_id is FAULT.
 * want_inject is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * injected and bytes_moved stay false on every path.
 * A unit note does not inject a live fault.
 */
SwarmNotNoFaultInject2Result SwarmNoteNotNoFaultInject2(const SwarmNotNoFaultInject2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFAULTINJECT2_H
