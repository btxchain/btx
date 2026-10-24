// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAMILYONLY_H
#define BTX_MODELNET_SWARM_FAMILYONLY_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. want_share asks this note to share
 * page bytes. same_family and compatible are flags, not a transfer.
 *
 * This note does not share or move KV bytes. shared and bytes_moved
 * stay false on every path. Family membership is not KV compatibility.
 */
struct SwarmFamilyOnly {
    std::string page_id;
    bool same_family{false};
    bool compatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting a page. shared and bytes_moved stay false on every path.
 */
struct SwarmFamilyOnlyResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a page without sharing or moving KV bytes.
 * Order, first match wins: an empty page_id is FAMILY.
 * same_family without compatible is FAMILY_NOT_COMPAT, even when want_share is true.
 * A different family is SEPARATE, even when compatible and want_share are true.
 * want_share on a compatible same family is HELD and err is cleared.
 * Otherwise the note is NOTED and err is clear.
 * shared and bytes_moved stay false on every path. Family membership is not KV compatibility.
 */
SwarmFamilyOnlyResult SwarmNoteFamilyOnly(const SwarmFamilyOnly& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAMILYONLY_H
