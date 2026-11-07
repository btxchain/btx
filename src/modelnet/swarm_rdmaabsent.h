// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RDMAABSENT_H
#define BTX_MODELNET_SWARM_RDMAABSENT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * An RDMA absence record. engine_id names the engine. adapter_absent is
 * true when the RDMA adapter is missing. want_move asks this note to move
 * bytes.
 *
 * A missing RDMA adapter is ENGINE_ABSENT and moves no bytes.
 */
struct SwarmRdmaAbsent {
    std::string engine_id;
    bool adapter_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting a missing RDMA adapter. moved stays false and
 * bytes_moved stays 0 on every path.
 */
struct SwarmRdmaAbsentResult {
    std::string code;
    bool moved{false};
    int64_t bytes_moved{0};
};

/**
 * Note an RDMA absence. A missing RDMA adapter moves no bytes.
 * Order, first match wins: an empty engine_id is ENGINE. adapter_absent
 * true is ENGINE_ABSENT, even when want_move is false. want_move true is
 * HELD. Otherwise the code is NOTED and err is cleared.
 * moved stays false and bytes_moved stays 0 on every path.
 */
SwarmRdmaAbsentResult SwarmNoteRdmaAbsent(const SwarmRdmaAbsent& engine, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RDMAABSENT_H
