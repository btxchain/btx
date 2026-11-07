// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_NAMES_H
#define BITCOIN_MODELNET_SWARM_DECODE_NAMES_H

#include <string>

namespace modelnet {

/** In-process engine. Pull echoes the stored public prompt one byte at a time. */
inline constexpr char kSwarmDecodeMemory[] = "memory";

/** Named production engines. They are not linked, so Pull does not emit bytes. */
inline constexpr char kSwarmDecodeVllm[] = "vllm";
inline constexpr char kSwarmDecodeSglang[] = "sglang";
inline constexpr char kSwarmDecodeLmcache[] = "lmcache";

/**
 * True for memory, vllm, sglang, and lmcache only.
 * The compare is bytewise. A different case or an extra byte is not a known engine.
 */
bool SwarmDecodeEngineIsKnown(const std::string& engine);

/** True only for the in-process memory engine. */
bool SwarmDecodeEngineIsMemory(const std::string& engine);

/**
 * True for vllm, sglang, and lmcache.
 * Those names may be stored. They do not link an engine and do not emit bytes.
 */
bool SwarmDecodeEngineIsProduction(const std::string& engine);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_NAMES_H
