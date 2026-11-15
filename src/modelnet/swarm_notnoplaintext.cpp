// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoplaintext.h>

#include <string>

namespace modelnet {

SwarmNotNoPlaintextResult SwarmNoteNotNoPlaintext(const SwarmNotNoPlaintext& note, std::string& err)
{
    SwarmNotNoPlaintextResult result;
    result.erased = false;
    result.bytes_moved = false;
    // erased and bytes_moved stay false on every path. Previously
    // delivered plaintext stays after revoke and is not erased.
    if (note.member_id.empty()) {
        result.code = "MEMBER";
        result.erased = false;
        result.bytes_moved = false;
        err = "MEMBER";
        return result;
    }
    if (note.revoked) {
        result.code = "RETAINED";
        result.erased = false;
        result.bytes_moved = false;
        err = "RETAINED";
        return result;
    }
    if (note.want_erase) {
        result.code = "RETAINED";
        result.erased = false;
        result.bytes_moved = false;
        err = "RETAINED";
        return result;
    }
    result.code = "NOTED";
    result.erased = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
