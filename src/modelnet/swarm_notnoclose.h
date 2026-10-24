// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLOSE_H
#define BTX_MODELNET_SWARM_NOTNOCLOSE_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_broadcast asks this note to
 * broadcast a close.
 *
 * An 8000-byte close size is not a measurement and this note broadcasts
 * nothing. broadcast stays false and assumed_bytes stays 0 on every path.
 */
struct SwarmNotNoClose {
    std::string channel_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a close that is not broadcast. broadcast stays false
 * and assumed_bytes stays 0 on every path. An 8000-byte close size is not
 * a measurement and this note broadcasts nothing.
 */
struct SwarmNotNoCloseResult {
    std::string code;
    bool broadcast{false};
    int assumed_bytes{0};
};

/**
 * Note a close without broadcasting it or recording an assumed size.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * want_broadcast is NOT_BROADCAST.
 * Otherwise the note is NOTED and err is clear.
 * broadcast stays false and assumed_bytes stays 0 on every path.
 * An 8000-byte close size is not a measurement and this note broadcasts
 * nothing.
 */
SwarmNotNoCloseResult SwarmNoteNotNoClose(const SwarmNotNoClose& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLOSE_H
