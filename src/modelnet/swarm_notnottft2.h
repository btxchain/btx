// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTTFT2_H
#define BTX_MODELNET_SWARM_NOTNOTTFT2_H

#include <string>

namespace modelnet {

/**
 * A unit note about time to first token for one sample. want_publish asks
 * this note to publish a time-to-first-token measurement.
 *
 * A unit note publishes no time to first token.
 * published stays false and ttft_us stays 0 on every path.
 */
struct SwarmNotNoTtft2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting time to first token. published stays false and
 * ttft_us stays 0 on every path.
 */
struct SwarmNotNoTtft2Result {
    std::string code;
    bool published{false};
    int ttft_us{0};
};

/**
 * Note a sample without publishing a time-to-first-token measurement.
 * Order, first match wins: an empty sample_id is SAMPLE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and ttft_us stays 0 on every path.
 * A unit note publishes no time to first token.
 */
SwarmNotNoTtft2Result SwarmNoteNotNoTtft2(const SwarmNotNoTtft2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTTFT2_H
