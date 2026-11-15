// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefundleaf2.h>

#include <string>

namespace modelnet {

SwarmNotNoRefundLeaf2Result SwarmNoteNotNoRefundLeaf2(const SwarmNotNoRefundLeaf2& note, std::string& err)
{
    SwarmNotNoRefundLeaf2Result result;
    result.built = false;
    // A contributor HTLC note builds no refund leaf.
    if (note.contract_id.empty()) {
        result.code = "CONTRACT";
        result.built = false;
        err = "CONTRACT";
        return result;
    }
    if (note.want_build) {
        result.code = "HELD";
        result.built = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.built = false;
    err.clear();
    return result;
}

} // namespace modelnet
