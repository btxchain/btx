// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGOVDRAIN2_H
#define BTX_MODELNET_SWARM_NOTNOGOVDRAIN2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one governor. idle records an idle governor.
 * want_keep asks this note to keep workers running.
 *
 * An idle governor drains workers to zero and does not keep them
 * running. workers stays 0 on every path.
 */
struct SwarmNotNoGovDrain2 {
    std::string governor_id;
    bool idle{false};
    bool want_keep{false};
};

/**
 * Outcome of noting an idle governor. workers stays 0 on every path.
 * An idle governor drains workers to zero and does not keep them running.
 */
struct SwarmNotNoGovDrain2Result {
    std::string code;
    int64_t workers{0};
};

/**
 * Note an idle governor without keeping workers running.
 * Order, first match wins: an empty governor_id is GOVERNOR. If idle
 * is true, the note is DRAINED even when want_keep is false. want_keep
 * is HELD. Otherwise the note is NOTED and err is cleared. workers
 * stays 0 on every path. An idle governor drains workers to zero.
 */
SwarmNotNoGovDrain2Result SwarmNoteNotNoGovDrain2(const SwarmNotNoGovDrain2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGOVDRAIN2_H
