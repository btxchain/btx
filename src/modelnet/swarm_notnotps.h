// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTPS_H
#define BTX_MODELNET_SWARM_NOTNOTPS_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish a
 * tokens-per-second measurement.
 *
 * A short generation is not a tokens-per-second measurement.
 * published stays false and tokens_per_sec stays 0 on every path.
 */
struct SwarmNotNoTps {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a tokens-per-second request. published stays false and
 * tokens_per_sec stays 0 on every path: a short generation is not a
 * tokens-per-second measurement.
 */
struct SwarmNotNoTpsResult {
    std::string code;
    bool published{false};
    int tokens_per_sec{0};
};

/**
 * Note a tokens-per-second request without measuring or publishing one.
 * Order, first match wins: an empty run_id is RUN.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false and tokens_per_sec stays 0 on every path.
 */
SwarmNotNoTpsResult SwarmNoteNotNoTps(const SwarmNotNoTps& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTPS_H
