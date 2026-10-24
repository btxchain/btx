// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOACCTONLY_H
#define BTX_MODELNET_SWARM_NOTNOACCTONLY_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one mesh. want_pay asks this note to pay.
 *
 * Paynet stays accounting only and this note pays nothing, so paid stays
 * false and atoms stays 0 on every path.
 */
struct SwarmNotNoAcctOnly {
    std::string mesh_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a mesh. paid stays false and atoms stays 0 on every
 * path. Paynet stays accounting only and this note pays nothing.
 */
struct SwarmNotNoAcctOnlyResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a mesh without paying.
 * Order, first match wins: an empty mesh_id is MESH. want_pay is
 * ACCOUNTING. Otherwise the note is NOTED and err is cleared. paid stays
 * false and atoms stays 0 on every path. Paynet stays accounting only and
 * this note pays nothing.
 */
SwarmNotNoAcctOnlyResult SwarmNoteNotNoAcctOnly(const SwarmNotNoAcctOnly& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOACCTONLY_H
