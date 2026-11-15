// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_COMPATFAM_H
#define BTX_MODELNET_SWARM_COMPATFAM_H

#include <string>

namespace modelnet {

/**
 * A family-compatibility record for one page. page_id names the page.
 * same_family records family membership. want_share asks this record
 * to share.
 *
 * Family membership is not compatibility. A share request is held.
 * It shares nothing. shared stays false on every path.
 */
struct SwarmCompatFam {
    std::string page_id;
    bool same_family{false};
    bool want_share{false};
};

/**
 * Outcome of noting family compatibility. shared stays false on every path.
 * A share request is held. It shares nothing.
 */
struct SwarmCompatFamResult {
    std::string code;
    bool shared{false};
};

/**
 * Note family compatibility without sharing.
 * Order, first match wins: an empty page_id is PAGE. same_family true
 * is NOT_COMPAT, even when want_share is false. want_share is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * shared stays false on every path.
 * Family membership is not compatibility.
 */
SwarmCompatFamResult SwarmNoteCompatFam(const SwarmCompatFam& page, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_COMPATFAM_H
