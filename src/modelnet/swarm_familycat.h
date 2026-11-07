// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAMILYCAT_H
#define BTX_MODELNET_SWARM_FAMILYCAT_H

#include <string>

namespace modelnet {

/**
 * A local family catalog entry. family_id names the family.
 * private_family, want_publish, and want_list are caller claims.
 *
 * A private family is not published. This catalog does not open a socket,
 * traverse NAT, or move bytes.
 *
 * A local catalog can list a public family and does not publish a private one.
 */
struct SwarmFamilyCat {
    std::string family_id;
    bool private_family{false};
    bool want_publish{false};
    bool want_list{false};
};

/**
 * Outcome of cataloging one family. published stays false on every path.
 */
struct SwarmFamilyCatResult {
    std::string code;
    bool published{false};
    bool listed{false};
};

/**
 * Catalog one family locally.
 * Order, first match wins: an empty family_id is FAMILY and listed is false.
 * private_family true is NOT_PUBLISHED and listed is false, even when
 * want_publish is false and want_list is true.
 * want_publish true is HELD and listed is true.
 * want_list true is NOTED, err is cleared, and listed is true.
 * Otherwise the code is NOTED, err is cleared, and listed is false.
 * published stays false on every path.
 * A local catalog can list a public family and does not publish a private one.
 */
SwarmFamilyCatResult SwarmCatalogFamily(const SwarmFamilyCat& family, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAMILYCAT_H
