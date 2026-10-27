// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_CODES_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_CODES_H

namespace modelnet {

/** Empty slot, empty fingerprint, or a move naming a slot that was never stored. */
inline constexpr char kSwarmKvMovePage[] = "PAGE";

/** Quantization is not "4bit", and not "full" with a non-empty body. Nothing is stored. */
inline constexpr char kSwarmKvMoveQuantization[] = "QUANTIZATION";

/** The slot is already stored. The first body stays. */
inline constexpr char kSwarmKvMoveReplay[] = "REPLAY";

/** nixl, mooncake, or rdma. Those engines copy nothing. */
inline constexpr char kSwarmKvMoveEngineAbsent[] = "ENGINE_ABSENT";

/** Memory engine, but the pages are not both resident KV with the same fingerprint. */
inline constexpr char kSwarmKvMoveNotCompat[] = "NOT_COMPAT";

/** Engine name is not memory, nixl, mooncake, or rdma. */
inline constexpr char kSwarmKvMoveEngine[] = "ENGINE";

inline constexpr char kSwarmKvMoveQuant4bit[] = "4bit";
inline constexpr char kSwarmKvMoveQuantFull[] = "full";

inline constexpr char kSwarmKvMoveEngineMemory[] = "memory";
inline constexpr char kSwarmKvMoveEngineNixl[] = "nixl";
inline constexpr char kSwarmKvMoveEngineMooncake[] = "mooncake";
inline constexpr char kSwarmKvMoveEngineRdma[] = "rdma";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_CODES_H
