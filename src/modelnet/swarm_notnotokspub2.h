// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTOKSPUB2_H
#define BTX_MODELNET_SWARM_NOTNOTOKSPUB2_H

#include <string>

namespace modelnet {

/**
 * A local note about one sample. want_publish asks this note to publish a
 * tokens-per-second measurement.
 *
 * This note publishes no tokens per second.
 * published stays false on every path.
 */
struct SwarmNotNoToksPub2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a tokens-per-second request. published stays false on
 * every path: this note publishes no tokens per second.
 */
struct SwarmNotNoToksPub2Result {
    std::string code;
    bool published{false};
};

/**
 * Note a tokens-per-second request without publishing one.
 * Order, first match wins: an empty sample_id is SAMPLE.
 * want_publish is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * published stays false on every path.
 * This note publishes no tokens per second.
 */
SwarmNotNoToksPub2Result SwarmNoteNotNoToksPub2(const SwarmNotNoToksPub2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTOKSPUB2_H
