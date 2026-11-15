// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFAMILY_H
#define BTX_MODELNET_SWARM_NOTNOFAMILY_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. page_id names the page. same_family
 * records family membership. compatible records compatibility.
 * want_share asks this note to share.
 *
 * Family membership is not compatibility. shared stays false and
 * bytes_moved stays false on every path.
 */
struct SwarmNotNoFamily {
    std::string page_id;
    bool same_family{false};
    bool compatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting a page. shared stays false and bytes_moved stays
 * false on every path. Family membership is not compatibility.
 */
struct SwarmNotNoFamilyResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a page without sharing it or moving bytes.
 * Order, first match wins: an empty page_id is PAGE.
 * If same_family is true and compatible is false, the note is
 * FAMILY_NOT_COMPAT even when want_share is false.
 * If same_family is false, the note is SEPARATE even when want_share
 * is false. want_share is NOT_SHARED.
 * Otherwise the note is NOTED and err is clear.
 * shared stays false and bytes_moved stays false on every path.
 * Family membership is not compatibility.
 */
SwarmNotNoFamilyResult SwarmNoteNotNoFamily(const SwarmNotNoFamily& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFAMILY_H
