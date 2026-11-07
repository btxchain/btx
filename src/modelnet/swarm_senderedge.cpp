// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_senderedge.h>

#include <cstdint>

namespace modelnet {

SwarmSenderEdgeResult SwarmNoteSenderEdge(const SwarmSenderEdge& edge, std::string& err)
{
    SwarmSenderEdgeResult result;
    result.fee_atoms = 0;
    result.cltv_added = false;
    if (edge.invoice_id.empty() || edge.hop < 1) {
        result.code = "EDGE";
        result.fee_atoms = 0;
        result.cltv_added = false;
        err = "EDGE";
        return result;
    }
    // NOT_FIRST wins even when want_fee or want_cltv is true.
    if (edge.hop != 1 || !edge.sender_owned) {
        result.code = "NOT_FIRST";
        result.fee_atoms = 0;
        result.cltv_added = false;
        err = "NOT_FIRST";
        return result;
    }
    // The sender's own first edge adds no fee. NO_FEE wins even when
    // want_cltv is true. Nothing is routed and nothing is broadcast.
    if (edge.want_fee) {
        result.code = "NO_FEE";
        result.fee_atoms = 0;
        result.cltv_added = false;
        err = "NO_FEE";
        return result;
    }
    if (edge.want_cltv) {
        result.code = "NO_CLTV";
        result.fee_atoms = 0;
        result.cltv_added = false;
        err = "NO_CLTV";
        return result;
    }
    result.code = "NOTED";
    result.fee_atoms = 0;
    result.cltv_added = false;
    err.clear();
    return result;
}

} // namespace modelnet
