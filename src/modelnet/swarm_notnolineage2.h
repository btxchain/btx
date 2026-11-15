// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLINEAGE2_H
#define BTX_MODELNET_SWARM_NOTNOLINEAGE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one hub listing. hub_listing marks the note as a
 * hub listing. want_authority asks this note to hold lineage authority.
 *
 * A hub listing is not lineage authority. authority stays false and
 * admitted stays false on every path.
 */
struct SwarmNotNoLineage2 {
    std::string model_id;
    bool hub_listing{false};
    bool want_authority{false};
};

/**
 * Outcome of noting a hub listing. authority stays false and admitted
 * stays false: a hub listing is not lineage authority.
 */
struct SwarmNotNoLineage2Result {
    std::string code;
    bool authority{false};
    bool admitted{false};
};

/**
 * Note a hub listing without granting lineage authority.
 * Order, first match wins: an empty model_id is MODEL. hub_listing is
 * NOT_AUTHORITY even when want_authority is false. want_authority is
 * HELD. Otherwise the note is NOTED and err is cleared. authority and
 * admitted stay false on every path. A hub listing is not lineage
 * authority.
 */
SwarmNotNoLineage2Result SwarmNoteNotNoLineage2(const SwarmNotNoLineage2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLINEAGE2_H
