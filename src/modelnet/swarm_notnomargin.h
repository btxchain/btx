// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMARGIN_H
#define BTX_MODELNET_SWARM_NOTNOMARGIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one close margin. blocks is the close margin in
 * blocks. want_broadcast asks this note to broadcast.
 *
 * A 160-block close margin is not a broadcast. This note does not
 * broadcast. broadcast stays false and applied_blocks stays 0 on every path.
 */
struct SwarmNotNoMargin {
    std::string channel_id;
    int64_t blocks{0};
    bool want_broadcast{false};
};

/**
 * Outcome of noting a close margin. broadcast stays false and
 * applied_blocks stays 0 on every path. A 160-block close margin is not
 * a broadcast.
 */
struct SwarmNotNoMarginResult {
    std::string code;
    bool broadcast{false};
    int64_t applied_blocks{0};
};

/**
 * Note a close margin without broadcasting.
 * Order, first match wins: an empty channel_id is CHANNEL. blocks other
 * than 160 is CAPPED even when want_broadcast is false. want_broadcast is
 * NOT_BROADCAST. Otherwise the note is NOTED and err is cleared.
 * broadcast stays false and applied_blocks stays 0 on every path. A
 * 160-block close margin is not a broadcast.
 */
SwarmNotNoMarginResult SwarmNoteNotNoMargin(const SwarmNotNoMargin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMARGIN_H
