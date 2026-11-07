// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleakpage2.h>

#include <string>

namespace modelnet {

SwarmNotNoLeakPage2Result SwarmNoteNotNoLeakPage2(const SwarmNotNoLeakPage2& note, std::string& err)
{
    SwarmNotNoLeakPage2Result result;
    result.read = false;
    result.bytes_moved = false;
    // A revoked member or a gradient leak reads no later page.
    if (note.member_id.empty()) {
        result.code = "MEMBER";
        result.read = false;
        result.bytes_moved = false;
        err = "MEMBER";
        return result;
    }
    if (note.revoked || note.gradient) {
        result.code = "NOT_READ";
        result.read = false;
        result.bytes_moved = false;
        err = "NOT_READ";
        return result;
    }
    if (note.want_read) {
        result.code = "HELD";
        result.read = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.read = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
