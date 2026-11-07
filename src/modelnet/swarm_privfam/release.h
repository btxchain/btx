// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_RELEASE_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_RELEASE_H

#include <modelnet/swarm_privfam/roster.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for Publish.
 * An empty family is FAMILY. An unknown family is FAMILY.
 * A stored private family is NOT_PUBLISHED.
 * This function does not modify the roster and does not publish.
 */
std::string SwarmPrivFamReleaseRefusal(const SwarmPrivFamRoster& roster, const std::string& family);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_RELEASE_H
