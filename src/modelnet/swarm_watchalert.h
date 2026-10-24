// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WATCHALERT_H
#define BTX_MODELNET_SWARM_WATCHALERT_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel watch. prior_secret_released asks for a
 * hashlock remedy. draining asks to drain and notify. stale_state asks for
 * a stale-state alert.
 *
 * secp_penalty and broadcast stay false on every path. Nothing is
 * broadcast. No hostnames or IPs are used.
 */
struct SwarmWatchAlert {
    std::string channel_id;
    bool prior_secret_released{false};
    bool draining{false};
    bool stale_state{false};
};

/**
 * Outcome of noting a channel watch. secp_penalty and broadcast stay false
 * on every path: there is no secp256k1 penalty and nothing is broadcast.
 */
struct SwarmWatchAlertResult {
    bool secp_penalty{false};
    bool broadcast{false};
    std::string code;
};

/**
 * Note a channel watch without a secp256k1 penalty and without a broadcast.
 * Order, first match wins: an empty channel_id is WATCH and err is WATCH.
 * prior_secret_released is HASHLOCK_REMEDY and err is clear, even when
 * draining or stale_state is true. draining is DRAIN_AND_NOTIFY and err is
 * clear, even when stale_state is true. stale_state is STALE_STATE_ALERT
 * and err is clear. Otherwise the note is NOTED and err is clear.
 * secp_penalty and broadcast stay false on every path. Nothing is broadcast.
 */
SwarmWatchAlertResult SwarmNoteWatchAlert(const SwarmWatchAlert& alert, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WATCHALERT_H
