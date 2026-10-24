// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock.h>

#include <cstdint>

namespace modelnet {

SwarmHashlockResult SwarmNoteHashlock(const SwarmHashlockRequest& hashlock, std::string& err)
{
    SwarmHashlockResult result;
    result.qualified = false;
    if (hashlock.invoice_id.empty() || hashlock.hash_len < 0 || hashlock.preimage_len < 0) {
        result.code = "HASH";
        err = "HASH";
        return result;
    }
    // HASH_LEN wins even when want_qualify is true.
    // A routed payment uses a 32-byte SHA-256 hashlock.
    if (hashlock.hash_len != 32) {
        result.code = "HASH_LEN";
        err = "HASH_LEN";
        return result;
    }
    // PREIMAGE wins even when want_qualify is true.
    // A routed payment uses a 32-byte preimage.
    if (hashlock.preimage_len != 32) {
        result.code = "PREIMAGE";
        err = "PREIMAGE";
        return result;
    }
    // Asking to qualify a route does not qualify one.
    if (hashlock.want_qualify) {
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
