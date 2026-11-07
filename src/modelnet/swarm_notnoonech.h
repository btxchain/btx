// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOONECH_H
#define BTX_MODELNET_SWARM_NOTNOONECH_H

#include <string>

namespace modelnet {

/**
 * A local note about one pool. pool_id names the pool.
 * want_open asks this note to open a channel.
 *
 * High-speed L2 is one channel for many pools. This note opens no
 * second channel. opened stays false and channels stays 0 on every path.
 */
struct SwarmNotNoOneCh {
    std::string pool_id;
    bool want_open{false};
};

/**
 * Outcome of noting a pool. opened stays false and channels stays 0
 * on every path. High-speed L2 is one channel for many pools. This
 * note opens no second channel.
 */
struct SwarmNotNoOneChResult {
    std::string code;
    bool opened{false};
    int channels{0};
};

/**
 * Note a pool without opening a second channel.
 * Order, first match wins: an empty pool_id is POOL.
 * want_open is ONE.
 * Otherwise the note is NOTED and err is cleared.
 * opened stays false and channels stays 0 on every path.
 * High-speed L2 is one channel for many pools. This note opens no
 * second channel.
 */
SwarmNotNoOneChResult SwarmNoteNotNoOneCh(const SwarmNotNoOneCh& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOONECH_H
