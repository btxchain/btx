// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMARGIN_H
#define BTX_MODELNET_SWARM_NOTMARGIN_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel close margin. blocks is the block count
 * recorded for the channel. want_close asks this note to close.
 *
 * The close margin is 160 blocks. This note does not close or broadcast.
 * closed and broadcast stay false on every path.
 */
struct SwarmNotMargin {
    std::string channel_id;
    int blocks{0};
    bool want_close{false};
};

/**
 * Outcome of noting a close margin. closed and broadcast stay false on
 * every path. The close margin is 160 blocks and this note does not close
 * or broadcast.
 */
struct SwarmNotMarginResult {
    std::string code;
    bool closed{false};
    bool broadcast{false};
};

/**
 * Note a close margin without closing or broadcasting.
 * Order, first match wins: an empty channel_id is CHANNEL. blocks other
 * than 160, or want_close, is HELD. Otherwise the note is NOTED and err
 * is clear.
 * closed and broadcast stay false on every path. The close margin is 160
 * blocks and this note does not close or broadcast.
 */
SwarmNotMarginResult SwarmNoteNotMargin(const SwarmNotMargin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMARGIN_H
