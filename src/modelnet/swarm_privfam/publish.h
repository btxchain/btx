// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_PUBLISH_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_PUBLISH_H

#include <modelnet/swarm_privfam/roster.h>
#include <modelnet/swarm_privfam/shelf.h>

#include <string>

namespace modelnet {

/**
 * Publish is refused.
 * A stored private family sets err to NOT_PUBLISHED. An empty family
 * and an unknown family set err to FAMILY. published() stays false.
 * The roster is unchanged. This does not connect or record a seed.
 */
bool SwarmPrivFamPublish(SwarmPrivFamShelf& shelf,
                          const SwarmPrivFamRoster& roster,
                          const std::string& family,
                          std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_PUBLISH_H
