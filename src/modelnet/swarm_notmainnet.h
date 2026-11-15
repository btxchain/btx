// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMAINNET_H
#define BTX_MODELNET_SWARM_NOTMAINNET_H

#include <string>

namespace modelnet {

/**
 * A local note about one request. want_mainnet asks this note to broadcast
 * and mine on mainnet.
 *
 * This note does not broadcast or mine. broadcast and mined stay false on
 * every path.
 */
struct SwarmNotMainnet {
    std::string request_id;
    bool want_mainnet{false};
};

/**
 * Outcome of noting a mainnet request. broadcast and mined stay false on
 * every path: this note does not broadcast or mine.
 */
struct SwarmNotMainnetResult {
    std::string code;
    bool broadcast{false};
    bool mined{false};
};

/**
 * Note a request without broadcasting or mining.
 * Order, first match wins: an empty request_id is REQUEST. want_mainnet
 * is MAINNET. Otherwise the note is NOTED and err is clear.
 * broadcast and mined stay false on every path. This note does not
 * broadcast or mine.
 */
SwarmNotMainnetResult SwarmNoteNotMainnet(const SwarmNotMainnet& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMAINNET_H
