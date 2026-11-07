// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MOONCAKEABS_H
#define BTX_MODELNET_SWARM_MOONCAKEABS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A Mooncake absence record. engine_id names the engine. adapter_absent
 * is true when the Mooncake adapter is missing. want_move asks this note
 * to move bytes.
 *
 * A missing Mooncake adapter is ENGINE_ABSENT and moves no bytes.
 */
struct SwarmMooncakeAbs {
    std::string engine_id;
    bool adapter_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting a missing Mooncake adapter. moved stays false and
 * bytes_moved stays 0 on every path.
 */
struct SwarmMooncakeAbsResult {
    std::string code;
    bool moved{false};
    int64_t bytes_moved{0};
};

/**
 * Note a Mooncake absence. A missing Mooncake adapter moves no bytes.
 * Order, first match wins: an empty engine_id is ENGINE. adapter_absent
 * true is ENGINE_ABSENT, even when want_move is false. want_move true is
 * HELD. Otherwise the code is NOTED and err is cleared.
 * moved stays false and bytes_moved stays 0 on every path.
 */
SwarmMooncakeAbsResult SwarmNoteMooncakeAbs(const SwarmMooncakeAbs& engine, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MOONCAKEABS_H
