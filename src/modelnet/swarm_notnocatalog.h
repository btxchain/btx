// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCATALOG_H
#define BTX_MODELNET_SWARM_NOTNOCATALOG_H

#include <string>

namespace modelnet {

/**
 * A local note about one catalog entry. want_authority asks this note to
 * treat the entry as lineage authority.
 *
 * A catalog entry is not lineage authority. authority and published stay
 * false on every path.
 */
struct SwarmNotNoCatalog {
    std::string entry_id;
    bool want_authority{false};
};

/**
 * Outcome of noting a catalog entry. authority and published stay false on
 * every path: a catalog entry is not lineage authority.
 */
struct SwarmNotNoCatalogResult {
    std::string code;
    bool authority{false};
    bool published{false};
};

/**
 * Note a catalog entry without granting lineage authority.
 * Order, first match wins: an empty entry_id is ENTRY. want_authority is
 * NOT_AUTHORITY. Otherwise the note is NOTED and err is clear.
 * authority and published stay false on every path. A catalog entry is
 * not lineage authority.
 */
SwarmNotNoCatalogResult SwarmNoteNotNoCatalog(const SwarmNotNoCatalog& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCATALOG_H
