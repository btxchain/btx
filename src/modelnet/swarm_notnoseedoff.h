// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEEDOFF_H
#define BTX_MODELNET_SWARM_NOTNOSEEDOFF_H

#include <string>

namespace modelnet {

/**
 * A local note about one seed. seed_id names the seed.
 * want_publish asks this note to publish it.
 *
 * An empty seed list is not an authority publish. published and authority
 * stay false on every path.
 */
struct SwarmNotNoSeedOff {
    std::string seed_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a seed. published and authority stay false on every
 * path. An empty seed list is not an authority publish.
 */
struct SwarmNotNoSeedOffResult {
    std::string code;
    bool published{false};
    bool authority{false};
};

/**
 * Note a seed without publishing authority.
 * Order, first match wins: an empty seed_id is SEED.
 * want_publish is NOT_AUTHORITY.
 * Otherwise the note is NOTED and err is cleared.
 * published and authority stay false on every path.
 * An empty seed list is not an authority publish.
 */
SwarmNotNoSeedOffResult SwarmNoteNotNoSeedOff(const SwarmNotNoSeedOff& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEEDOFF_H
