// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEXIT_H
#define BTX_MODELNET_SWARM_NOTNOEXIT_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_broadcast asks this note to
 * broadcast an exit transaction.
 *
 * This note broadcasts no exit transaction. broadcast and confirmed
 * stay false on every path.
 */
struct SwarmNotNoExit {
    std::string channel_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a channel. broadcast and confirmed stay false on
 * every path. This note broadcasts no exit transaction.
 */
struct SwarmNotNoExitResult {
    std::string code;
    bool broadcast{false};
    bool confirmed{false};
};

/**
 * Note a channel without broadcasting an exit transaction.
 * Order, first match wins: an empty channel_id is CHANNEL. want_broadcast
 * is NOT_BROADCAST. Otherwise the note is NOTED and err is cleared.
 * broadcast and confirmed stay false on every path. This note broadcasts
 * no exit transaction.
 */
SwarmNotNoExitResult SwarmNoteNotNoExit(const SwarmNotNoExit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEXIT_H
