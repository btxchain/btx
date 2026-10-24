// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_FLAG_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_FLAG_H

#include <string>

namespace modelnet {

/**
 * How one Offer relates to privacy, before the roster is consulted.
 * Private is the only result that may be stored. The other results
 * store nothing.
 */
enum class SwarmPrivFamFlag {
    Private,
    Public,
    Family,
};

/**
 * Classify one Offer. This does not look at families already stored.
 * An empty family is Family. private_flag false is Public.
 * private_flag true with a non-empty family is Private.
 */
SwarmPrivFamFlag SwarmPrivFamClassify(const std::string& family, bool private_flag);

/**
 * Refusal code for a non-private result, or nullptr for Private.
 */
const char* SwarmPrivFamFlagCode(SwarmPrivFamFlag flag);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_FLAG_H
