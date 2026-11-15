// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBASE_H
#define BTX_MODELNET_SWARM_NOTNOBASE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one generation run. want_publish asks this note to
 * publish a multiplier.
 *
 * This note does not publish a multiplier. published stays false and
 * multiplier stays 0 on every path. A baseline note publishes no
 * multiplier.
 */
struct SwarmNotNoBase {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a generation run. published stays false and
 * multiplier stays 0 on every path.
 */
struct SwarmNotNoBaseResult {
    std::string code;
    bool published{false};
    int64_t multiplier{0};
};

/**
 * Note a generation run without publishing a multiplier.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and multiplier stays 0 on every path.
 * A baseline note publishes no multiplier.
 */
SwarmNotNoBaseResult SwarmNoteNotNoBase(const SwarmNotNoBase& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBASE_H
