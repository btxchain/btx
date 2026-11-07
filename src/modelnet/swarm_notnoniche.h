// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONICHE_H
#define BTX_MODELNET_SWARM_NOTNONICHE_H

#include <string>

namespace modelnet {

/**
 * A local note about a niche. niche_id names the niche. same_niche is
 * false when the niches are distinct. want_merge asks this note to merge
 * niches.
 *
 * Distinct niches stay separate. merged and shared stay false on every
 * path.
 */
struct SwarmNotNoNiche {
    std::string niche_id;
    bool same_niche{false};
    bool want_merge{false};
};

/**
 * Outcome of noting a niche. merged and shared stay false on every path:
 * distinct niches stay separate.
 */
struct SwarmNotNoNicheResult {
    std::string code;
    bool merged{false};
    bool shared{false};
};

/**
 * Note a niche without merging it.
 * Order, first match wins: an empty niche_id is NICHE. same_niche false
 * is SEPARATE even when want_merge is false. want_merge is SEPARATE.
 * Otherwise the note is NOTED and err is clear.
 * merged and shared stay false on every path. Distinct niches stay
 * separate.
 */
SwarmNotNoNicheResult SwarmNoteNotNoNiche(const SwarmNotNoNiche& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONICHE_H
