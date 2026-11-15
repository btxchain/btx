// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTOKPS2_H
#define BTX_MODELNET_SWARM_NOTNOTOKPS2_H

#include <string>

namespace modelnet {

/**
 * A local note about one sample. want_publish asks this note to publish a
 * tokens-per-second measurement.
 *
 * A unit note publishes no tokens per second.
 * published stays false and tokens_per_sec stays 0 on every path.
 */
struct SwarmNotNoTokps2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a tokens-per-second request. published stays false and
 * tokens_per_sec stays 0 on every path: a unit note publishes no tokens
 * per second.
 */
struct SwarmNotNoTokps2Result {
    std::string code;
    bool published{false};
    int tokens_per_sec{0};
};

/**
 * Note a tokens-per-second request without measuring or publishing one.
 * Order, first match wins: an empty sample_id is SAMPLE.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false and tokens_per_sec stays 0 on every path.
 * A unit note publishes no tokens per second.
 */
SwarmNotNoTokps2Result SwarmNoteNotNoTokps2(const SwarmNotNoTokps2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTOKPS2_H
