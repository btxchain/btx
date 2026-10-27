// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_POOLREF_H
#define BTX_MODELNET_SWARM_POOLREF_H

#include <string>

namespace modelnet {

/**
 * A local note about one pool channel. outpoint and pool_id are opaque
 * strings. already_owned says this outpoint already has a channel.
 * want_open asks this note to open a channel. want_reference asks this
 * note to reference a channel.
 *
 * A second pool cannot open another channel on the same outpoint. This
 * note does not open a channel and does not broadcast. opened stays false
 * on every path. No hostnames or IPs are used.
 */
struct SwarmPoolChannel {
    std::string outpoint;
    std::string pool_id;
    bool already_owned{false};
    bool want_open{false};
    bool want_reference{false};
};

/**
 * Outcome of noting a pool channel. opened stays false: this note does
 * not open a channel and does not broadcast.
 */
struct SwarmPoolChannelResult {
    bool opened{false};
    std::string code;
};

/**
 * Note a pool channel without opening one.
 * Order, first match wins: an empty outpoint or an empty pool_id is
 * CHANNEL. want_open on an already owned outpoint is COLLATERAL_REUSE,
 * including when want_reference is true. A second pool cannot open
 * another channel on the same outpoint. want_open is HELD and err is
 * cleared. This note does not open a channel. want_reference without
 * already_owned is NO_CHANNEL. Otherwise the note is NOTED and err is
 * cleared. A reference of an already owned channel is NOTED and still
 * does not open.
 * opened stays false on every path. Nothing is broadcast.
 */
SwarmPoolChannelResult SwarmNotePoolChannel(const SwarmPoolChannel& channel, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_POOLREF_H
