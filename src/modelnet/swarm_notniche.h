// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNICHE_H
#define BTX_MODELNET_SWARM_NOTNICHE_H

#include <string>

namespace modelnet {

/**
 * A local note about a niche. niche_id names the niche. want_merge
 * asks this note to merge niches.
 *
 * Niches stay separate. merged stays false on every path.
 */
struct SwarmNotNiche {
    std::string niche_id;
    bool want_merge{false};
};

/**
 * Outcome of noting a niche. merged stays false on every path:
 * niches stay separate.
 */
struct SwarmNotNicheResult {
    std::string code;
    bool merged{false};
};

/**
 * Note a niche without merging it.
 * Order, first match wins: an empty niche_id is NICHE. want_merge
 * is SEPARATE. Otherwise the note is NOTED and err is clear.
 * merged stays false on every path. Niches stay separate.
 */
SwarmNotNicheResult SwarmNoteNotNiche(const SwarmNotNiche& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNICHE_H
