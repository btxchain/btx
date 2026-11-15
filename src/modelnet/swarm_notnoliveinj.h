// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLIVEINJ_H
#define BTX_MODELNET_SWARM_NOTNOLIVEINJ_H

#include <string>

namespace modelnet {

/**
 * A unit note about one fault. want_inject asks this note to inject a
 * live fault.
 *
 * A unit note injects no live fault and moves no bytes.
 * injected and bytes_moved stay false on every path.
 */
struct SwarmNotNoLiveInj {
    std::string fault_id;
    bool want_inject{false};
};

/**
 * Outcome of noting a fault. injected and bytes_moved stay false on
 * every path: a unit note injects no live fault and moves no bytes.
 */
struct SwarmNotNoLiveInjResult {
    std::string code;
    bool injected{false};
    bool bytes_moved{false};
};

/**
 * Note a fault without injecting it and without moving bytes.
 * Order, first match wins: an empty fault_id is FAULT.
 * want_inject is NOT_INJECTED.
 * Otherwise the note is NOTED and err is cleared.
 * injected and bytes_moved stay false on every path.
 * A unit note injects no live fault and moves no bytes.
 */
SwarmNotNoLiveInjResult SwarmNoteNotNoLiveInj(const SwarmNotNoLiveInj& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLIVEINJ_H
