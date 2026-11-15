// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ENGADAPTER_H
#define BTX_MODELNET_SWARM_ENGADAPTER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Caller description of an engine adapter. transfer_id names the transfer.
 * engine_name names the engine. installed, cuda_ops, and want_move are
 * caller claims. bytes is the claimed size.
 *
 * An adapter names an engine and moves no bytes.
 */
struct SwarmEngAdapter {
    std::string transfer_id;
    std::string engine_name;
    bool installed{false};
    bool cuda_ops{false};
    bool want_move{false};
    int64_t bytes{0};
};

/**
 * Outcome of naming an engine. moved stays false, bytes_moved stays 0, and
 * advertised stays false on every path.
 */
struct SwarmEngAdapterResult {
    std::string code;
    bool moved{false};
    int64_t bytes_moved{0};
    bool advertised{false};
};

/**
 * Name an engine for a transfer.
 * Order, first match wins: an empty transfer_id is TRANSFER. An empty
 * engine_name is ENGINE. installed false is ENGINE_ABSENT, even when
 * want_move is false. cuda_ops false is ENGINE_ABSENT. want_move true is
 * HELD. Otherwise the code is NOTED and err is cleared.
 * moved stays false, bytes_moved stays 0, and advertised stays false on
 * every path.
 * An adapter names an engine and moves no bytes.
 */
SwarmEngAdapterResult SwarmAdaptEngine(const SwarmEngAdapter& adapter, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ENGADAPTER_H
