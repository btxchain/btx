// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCKPTTIME_H
#define BTX_MODELNET_SWARM_NOTCKPTTIME_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about checkpoint time for one job. checkpoint_saved says
 * a checkpoint was stored. want_publish asks this note to publish a time.
 *
 * This note does not publish a time or recover a checkpoint. published
 * and recovered stay false, and seconds stays 0, on every path.
 */
struct SwarmNotCkptTime {
    std::string job_id;
    bool checkpoint_saved{false};
    bool want_publish{false};
};

/**
 * Outcome of noting checkpoint time. published and recovered stay false,
 * and seconds stays 0, on every path.
 */
struct SwarmNotCkptTimeResult {
    std::string code;
    bool published{false};
    bool recovered{false};
    int64_t seconds{0};
};

/**
 * Note checkpoint time without publishing or recovering it.
 * Order, first match wins: an empty job_id is JOB. A note that is not
 * checkpoint_saved is NO_CHECKPOINT, even if want_publish is set.
 * want_publish is UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published and recovered stay false, and seconds stays 0, on every path.
 */
SwarmNotCkptTimeResult SwarmNoteNotCkptTime(const SwarmNotCkptTime& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCKPTTIME_H
