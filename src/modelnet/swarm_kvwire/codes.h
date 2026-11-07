// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVWIRE_CODES_H
#define BITCOIN_MODELNET_SWARM_KVWIRE_CODES_H

namespace modelnet {

/** Empty body. Nothing is written and nothing is read. */
inline constexpr char kSwarmKvWirePage[] = "PAGE";

/** nixl, mooncake, or rdma. Those engines move nothing. */
inline constexpr char kSwarmKvWireEngineAbsent[] = "ENGINE_ABSENT";

/** Engine name is not nixl, mooncake, or rdma. Nothing is moved. */
inline constexpr char kSwarmKvWireEngine[] = "ENGINE";

/** The pair could not be created, or a write or read failed. Nothing is kept. */
inline constexpr char kSwarmKvWireIo[] = "IO";

/** Transfer stays on this engine. */
inline constexpr char kSwarmKvWireEngineLocal[] = "local";

inline constexpr char kSwarmKvWireEngineNixl[] = "nixl";
inline constexpr char kSwarmKvWireEngineMooncake[] = "mooncake";
inline constexpr char kSwarmKvWireEngineRdma[] = "rdma";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVWIRE_CODES_H
