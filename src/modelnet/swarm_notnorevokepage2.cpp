// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevokepage2.h>

#include <string>

namespace modelnet {

SwarmNotNoRevokePage2Result SwarmNoteNotNoRevokePage2(const SwarmNotNoRevokePage2& note, std::string& err)
{
    SwarmNotNoRevokePage2Result result;
    result.read = false;
    // A revoked member reads no later page.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.read = false;
        err = "PAGE";
        return result;
    }
    if (note.revoked) {
        result.code = "NOT_READ";
        result.read = false;
        err = "NOT_READ";
        return result;
    }
    if (note.want_read) {
        result.code = "HELD";
        result.read = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.read = false;
    err.clear();
    return result;
}

} // namespace modelnet
