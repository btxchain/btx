// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_prefixbook.h>

namespace modelnet {

// A matching prefix can be noted locally. Family membership does not share a page, and no bytes move.
SwarmPrefixBookResult SwarmMatchPrefix(const SwarmPrefixBook& page, std::string& err)
{
    SwarmPrefixBookResult result;
    result.shared = false;
    result.bytes_moved = 0;
    result.compatible = false;

    if (page.page_id.empty()) {
        result.code = "PAGE";
        err = "PAGE";
        result.compatible = false;
        result.shared = false;
        result.bytes_moved = 0;
        return result;
    }
    // Family membership is not compatibility.
    if (page.same_family && !page.same_prefix) {
        result.code = "NOT_COMPAT";
        err = "NOT_COMPAT";
        result.compatible = false;
        result.shared = false;
        result.bytes_moved = 0;
        return result;
    }
    if (!page.same_prefix) {
        result.code = "PREFIX";
        err = "PREFIX";
        result.compatible = false;
        result.shared = false;
        result.bytes_moved = 0;
        return result;
    }
    if (!page.engine_present) {
        result.code = "ENGINE_ABSENT";
        err = "ENGINE_ABSENT";
        result.compatible = false;
        result.shared = false;
        result.bytes_moved = 0;
        return result;
    }
    if (page.want_share) {
        result.code = "HELD";
        err = "HELD";
        result.compatible = true;
        result.shared = false;
        result.bytes_moved = 0;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.compatible = true;
    result.shared = false;
    result.bytes_moved = 0;
    return result;
}

} // namespace modelnet
