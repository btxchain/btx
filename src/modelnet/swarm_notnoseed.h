// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEED_H
#define BTX_MODELNET_SWARM_NOTNOSEED_H

#include <string>

namespace modelnet {

/**
 * A local note about one seed. want_publish asks this note to publish it.
 *
 * An empty DNS seed list publishes no authority. published and authority
 * stay false on every path.
 */
struct SwarmNotNoSeed {
    std::string seed_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a seed. published and authority stay false on every
 * path. An empty DNS seed list publishes no authority.
 */
struct SwarmNotNoSeedResult {
    std::string code;
    bool published{false};
    bool authority{false};
};

/**
 * Note a seed without publishing authority.
 * Order, first match wins: an empty seed_id is SEED.
 * want_publish is NOT_AUTHORITY.
 * Otherwise the note is NOTED and err is clear.
 * published and authority stay false on every path.
 * An empty DNS seed list publishes no authority.
 */
SwarmNotNoSeedResult SwarmNoteNotNoSeed(const SwarmNotNoSeed& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEED_H
