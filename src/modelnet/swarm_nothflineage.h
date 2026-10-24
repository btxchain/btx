// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTHFLINEAGE_H
#define BTX_MODELNET_SWARM_NOTHFLINEAGE_H

#include <string>

namespace modelnet {

/**
 * A local note about one Hugging Face import origin. want_authority asks
 * this note to treat the origin as lineage authority.
 *
 * A Hugging Face import origin is not lineage authority and publish-back
 * is not authority. This note publishes nothing. authority stays false
 * and published stays false on every path.
 */
struct SwarmNotHfLineage {
    std::string origin_id;
    bool want_authority{false};
};

/**
 * Outcome of noting a Hugging Face import origin. authority stays false
 * and published stays false: this note publishes nothing.
 */
struct SwarmNotHfLineageResult {
    std::string code;
    bool authority{false};
    bool published{false};
};

/**
 * Note a Hugging Face import origin without granting lineage authority.
 * Order, first match wins: an empty origin_id is ORIGIN. want_authority
 * is NOT_AUTHORITY. Otherwise the note is NOTED and err is cleared.
 * authority stays false and published stays false on every path. A
 * Hugging Face import origin is not lineage authority and publish-back
 * is not authority. This note publishes nothing.
 */
SwarmNotHfLineageResult SwarmNoteNotHfLineage(const SwarmNotHfLineage& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTHFLINEAGE_H
