// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_QUANTIZATION_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_QUANTIZATION_H

#include <string>

namespace modelnet {

/** How an offer would sit in the family, the KV cache, and the cohort. */
enum class SwarmKvPlaceQuant : int {
    /** Not an accepted profile. The caller stores nothing. */
    Reject = 0,
    /** "4bit". Family only. */
    Family = 1,
    /** "full" with a non-empty checkpoint and a non-empty recipe. */
    Cohort = 2,
};

/**
 * Classify a quantization profile.
 * "4bit" is family-only. Checkpoint and recipe are ignored for that profile.
 * "full" is a cohort profile only when checkpoint and recipe are both non-empty.
 * Every other string, including "full" with an empty checkpoint or recipe, is Reject.
 */
SwarmKvPlaceQuant SwarmKvPlaceClassify(const std::string& quantization, const std::string& checkpoint,
                                       const std::string& recipe);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_QUANTIZATION_H
