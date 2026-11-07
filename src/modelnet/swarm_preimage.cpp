// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimage.h>

#include <cstdint>

namespace modelnet {

SwarmPreimageResult SwarmNotePreimage(const SwarmPreimage& preimage, std::string& err)
{
    SwarmPreimageResult result;
    result.qualified = false;
    if (preimage.invoice_id.empty() || preimage.preimage_len < 0) {
        result.code = "PREIMAGE";
        err = "PREIMAGE";
        return result;
    }
    // LEN wins even when want_route is true. A routed hashlock needs a 32-byte preimage.
    if (preimage.preimage_len != 32) {
        result.code = "LEN";
        err = "LEN";
        return result;
    }
    // A 32-byte preimage is not a qualified multi-hop route.
    if (preimage.want_route) {
        result.code = "HELD";
        result.qualified = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
