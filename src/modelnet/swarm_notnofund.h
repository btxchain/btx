// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFUND_H
#define BTX_MODELNET_SWARM_NOTNOFUND_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_broadcast asks this note to
 * reach a funding broadcast.
 *
 * This note does not reach a funding broadcast or a funding
 * confirmation. broadcast and confirmed stay false on every path.
 */
struct SwarmNotNoFund {
    std::string channel_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a channel. broadcast and confirmed stay false on
 * every path. This note does not reach a funding broadcast or a funding
 * confirmation.
 */
struct SwarmNotNoFundResult {
    std::string code;
    bool broadcast{false};
    bool confirmed{false};
};

/**
 * Note a channel without a funding broadcast or a funding confirmation.
 * Order, first match wins: an empty channel_id is CHANNEL. want_broadcast
 * is NOT_OPEN. Otherwise the note is NOTED and err is cleared. broadcast
 * and confirmed stay false on every path. This note does not reach a
 * funding broadcast or a funding confirmation.
 */
SwarmNotNoFundResult SwarmNoteNotNoFund(const SwarmNotNoFund& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFUND_H
