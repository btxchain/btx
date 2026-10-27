// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_RECORD_H
#define BITCOIN_MODELNET_SWARM_DECODE_RECORD_H

#include <string>

namespace modelnet {

/**
 * One open decode session.
 * id is the session key stored by Open.
 * engine is memory, vllm, sglang, or lmcache.
 * prompt is the first public prompt, or empty until Prompt stores one.
 * The stored prompt is not generated text. text() stays empty until Pull appends a byte.
 */
struct SwarmDecodeSession {
    std::string id;
    std::string engine;
    std::string prompt;
    bool prompt_stored{false};
};

/**
 * A fresh session.
 * prompt stays empty and prompt_stored stays false.
 * Open stores the engine name. It does not append bytes.
 */
SwarmDecodeSession SwarmDecodeMakeSession(const std::string& id, const std::string& engine);

/**
 * True when id is non-empty, engine is a known name, and no prompt is attached yet.
 * A private prompt and an empty prompt are not usable records.
 */
bool SwarmDecodeSessionUsable(const SwarmDecodeSession& session);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_RECORD_H
