// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LORA_H
#define BTX_MODELNET_SWARM_LORA_H

#include <string>

namespace modelnet {

/**
 * Caller proof that a KV page may be reused. The flags are the proof.
 * This request does not carry page bytes and does not name a model file.
 */
struct SwarmKvReuseRequest {
    bool same_weights{false};
    bool same_tokenizer{false};
    bool same_quantization{false};
    bool same_adapter{false};
    bool approximate_requested{false};
};

/**
 * An admission answer. exact stays false unless the caller proves an
 * exact page match. Approximate reuse is never admitted. This result
 * does not carry page bytes.
 */
struct SwarmKvReuseResult {
    bool admitted{false};
    bool exact{false};
    std::string code;
};

/**
 * Admits KV reuse only when the caller proves an exact page match.
 * exact stays false unless that proof is present. Approximate reuse is
 * never admitted. This flag compare does not move bytes and does not
 * load a model.
 *
 * Order: approximate_requested true is APPROXIMATE, admitted false, and
 * exact false, even when the other flags are true. Any of same_weights,
 * same_tokenizer, same_quantization, or same_adapter false is
 * INCOMPATIBLE, admitted false, and exact false. Otherwise the result is
 * EXACT, admitted true, exact true, and err is cleared.
 */
SwarmKvReuseResult SwarmAdmitKvReuse(const SwarmKvReuseRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LORA_H
