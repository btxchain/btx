// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_CODES_H
#define BITCOIN_MODELNET_SWARM_DECODE_CODES_H

namespace modelnet {

/** The session id is empty, or the session is not open. Nothing new is stored. */
inline constexpr char kSwarmDecodeSession[] = "SESSION";

/** The engine name is not memory, vllm, sglang, or lmcache. Nothing is stored. */
inline constexpr char kSwarmDecodeEngine[] = "ENGINE";

/** This session is already open, or the same public prompt is already stored. The first value stays. */
inline constexpr char kSwarmDecodeReplay[] = "REPLAY";

/** The prompt is private. Nothing is stored. */
inline constexpr char kSwarmDecodePrivateData[] = "PRIVATE_DATA";

/** The public prompt is empty, or Pull was asked before a public prompt was stored. */
inline constexpr char kSwarmDecodePrompt[] = "PROMPT";

/** A different public prompt is already stored. The first prompt stays. */
inline constexpr char kSwarmDecodeHeld[] = "HELD";

/** vllm, sglang, and lmcache are not linked. Pull appends nothing. */
inline constexpr char kSwarmDecodeEngineAbsent[] = "ENGINE_ABSENT";

/** The memory stream has already appended the whole prompt, or 8 bytes. */
inline constexpr char kSwarmDecodeDone[] = "DONE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_CODES_H
