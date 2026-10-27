// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLIVE_H
#define BTX_MODELNET_SWARM_NOTNOLIVE_H

#include <string>

namespace modelnet {

/**
 * A local recovery note about one fault. want_inject asks this note to
 * inject a live fault.
 *
 * A local recovery note is not a live fault injection. injected and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoLive {
    std::string fault_id;
    bool want_inject{false};
};

/**
 * Outcome of noting a recovery. injected and bytes_moved stay false on
 * every path: a local recovery note is not a live fault injection.
 */
struct SwarmNotNoLiveResult {
    std::string code;
    bool injected{false};
    bool bytes_moved{false};
};

/**
 * Note a recovery without injecting a live fault.
 * Order, first match wins: an empty fault_id is FAULT.
 * want_inject is NOT_INJECTED.
 * Otherwise the note is NOTED and err is clear.
 * injected and bytes_moved stay false on every path. A local recovery
 * note is not a live fault injection.
 */
SwarmNotNoLiveResult SwarmNoteNotNoLive(const SwarmNotNoLive& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLIVE_H
