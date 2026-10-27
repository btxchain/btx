// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoacctonly.h>

#include <string>
#include <cstdint>

namespace modelnet {

SwarmNotNoAcctOnlyResult SwarmNoteNotNoAcctOnly(const SwarmNotNoAcctOnly& note, std::string& err)
{
    SwarmNotNoAcctOnlyResult result;
    result.paid = false;
    result.atoms = 0;
    // Paynet stays accounting only and this note pays nothing.
    if (note.mesh_id.empty()) {
        result.code = "MESH";
        result.paid = false;
        result.atoms = 0;
        err = "MESH";
        return result;
    }
    if (note.want_pay) {
        result.code = "ACCOUNTING";
        result.paid = false;
        result.atoms = 0;
        err = "ACCOUNTING";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
