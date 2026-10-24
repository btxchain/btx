// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_truncpage.h>

#include <cstdint>

namespace modelnet {

SwarmTruncatedPageResult SwarmNoteTruncatedPage(const SwarmTruncatedPage& page, std::string& err)
{
    SwarmTruncatedPageResult result;
    result.reusable = false;
    result.bytes_moved = false;
    if (page.page_id.empty() || page.expected_bytes < 1 || page.received_bytes < 0) {
        result.code = "PAGE";
        err = "PAGE";
        return result;
    }
    if (page.received_bytes != page.expected_bytes) {
        result.code = "TRUNCATED";
        err = "TRUNCATED";
        return result;
    }
    if (!page.compatible) {
        result.code = "INCOMPATIBLE";
        err = "INCOMPATIBLE";
        return result;
    }
    result.reusable = false;
    result.bytes_moved = false;
    result.code = "HELD";
    err.clear();
    return result;
}

} // namespace modelnet
