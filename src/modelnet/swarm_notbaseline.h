// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTBASELINE_H
#define BTX_MODELNET_SWARM_NOTBASELINE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one generation run. want_publish asks this note to
 * publish the run as a baseline.
 *
 * This note does not publish a baseline. published stays false and
 * tokens_per_sec stays 0 on every path. A four-token generation is not
 * a baseline.
 */
struct SwarmNotBaseline {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a generation run. published stays false and
 * tokens_per_sec stays 0 on every path.
 */
struct SwarmNotBaselineResult {
    std::string code;
    bool published{false};
    int64_t tokens_per_sec{0};
};

/**
 * Note a generation run without publishing a baseline.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and tokens_per_sec stays 0 on every path.
 * A four-token generation is not a baseline.
 */
SwarmNotBaselineResult SwarmNoteNotBaseline(const SwarmNotBaseline& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTBASELINE_H
