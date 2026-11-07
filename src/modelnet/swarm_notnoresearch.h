// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORESEARCH_H
#define BTX_MODELNET_SWARM_NOTNORESEARCH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one key. research_key records whether this key is
 * a research key. want_spend asks this note to spend it.
 *
 * A research key never receives a spend key and spends nothing. spent
 * stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoResearch {
    std::string key_id;
    bool research_key{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a key. spent stays false and atoms stays 0 on every
 * path. A research key never receives a spend key and spends nothing.
 */
struct SwarmNotNoResearchResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a key without spending it. Order, first match wins: an empty
 * key_id is KEY. research_key true is NO_SPEND even when want_spend is
 * false. want_spend is NO_SPEND. Otherwise the note is NOTED and err is
 * cleared. spent stays false and atoms stays 0 on every path. A research
 * key never receives a spend key and spends nothing.
 */
SwarmNotNoResearchResult SwarmNoteNotNoResearch(const SwarmNotNoResearch& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORESEARCH_H
