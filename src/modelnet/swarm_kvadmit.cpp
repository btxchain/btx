// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvadmit.h>

namespace modelnet {

// A KV page can be admitted locally and still moves no bytes.
SwarmKvAdmitResult SwarmAdmitKvPage(const SwarmKvAdmit& page, std::string& err)
{
    SwarmKvAdmitResult result;
    result.moved = false;
    result.bytes_moved = 0;
    result.admitted = false;

    if (page.page_id.empty()) {
        result.code = "PAGE";
        err = "PAGE";
        result.moved = false;
        result.bytes_moved = 0;
        return result;
    }
    if (page.revoked) {
        result.code = "REVOKED";
        err = "REVOKED";
        result.moved = false;
        result.bytes_moved = 0;
        return result;
    }
    if (!page.same_prefix) {
        result.code = "PREFIX";
        err = "PREFIX";
        result.moved = false;
        result.bytes_moved = 0;
        return result;
    }
    if (!page.engine_present) {
        result.code = "ENGINE_ABSENT";
        err = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = 0;
        return result;
    }
    if (page.want_move) {
        result.code = "HELD";
        err = "HELD";
        result.admitted = true;
        result.moved = false;
        result.bytes_moved = 0;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.admitted = true;
    result.moved = false;
    result.bytes_moved = 0;
    return result;
}

} // namespace modelnet
