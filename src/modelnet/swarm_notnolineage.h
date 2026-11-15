// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLINEAGE_H
#define BTX_MODELNET_SWARM_NOTNOLINEAGE_H

#include <string>

namespace modelnet {

/**
 * A local note about one hub listing. want_authority asks this note to
 * treat the listing as lineage authority.
 *
 * A hub listing is not lineage authority and publishes nothing. authority
 * stays false and published stays false on every path.
 */
struct SwarmNotNoLineage {
    std::string model_id;
    bool want_authority{false};
};

/**
 * Outcome of noting a hub listing. authority stays false and published
 * stays false: a hub listing publishes nothing.
 */
struct SwarmNotNoLineageResult {
    std::string code;
    bool authority{false};
    bool published{false};
};

/**
 * Note a hub listing without granting lineage authority.
 * Order, first match wins: an empty model_id is MODEL. want_authority
 * is NOT_AUTHORITY. Otherwise the note is NOTED and err is cleared.
 * authority stays false and published stays false on every path. A hub
 * listing is not lineage authority and publishes nothing.
 */
SwarmNotNoLineageResult SwarmNoteNotNoLineage(const SwarmNotNoLineage& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLINEAGE_H
