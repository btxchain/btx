// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifestbind.h>

namespace modelnet {

// A manifest root stays inactive until every child matches, and this record streams nothing.
SwarmManifestBindResult SwarmBindChildren(const SwarmManifestBind& bind, std::string& err)
{
    SwarmManifestBindResult result;
    result.activated = false;
    result.bytes_streamed = false;

    if (bind.root_id.empty()) {
        result.code = "ROOT";
        err = "ROOT";
        result.activated = false;
        result.bytes_streamed = false;
        return result;
    }
    if (bind.children <= 0) {
        result.code = "EMPTY";
        err = "EMPTY";
        result.activated = false;
        result.bytes_streamed = false;
        return result;
    }
    if (bind.matched < 0 || bind.matched > bind.children) {
        result.code = "RANGE";
        err = "RANGE";
        result.activated = false;
        result.bytes_streamed = false;
        return result;
    }
    if (bind.matched != bind.children) {
        result.code = "INCOMPLETE";
        err = "INCOMPLETE";
        result.activated = false;
        result.bytes_streamed = false;
        return result;
    }
    if (bind.want_activate) {
        result.code = "HELD";
        err = "HELD";
        result.activated = false;
        result.bytes_streamed = false;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.activated = false;
    result.bytes_streamed = false;
    return result;
}

} // namespace modelnet
