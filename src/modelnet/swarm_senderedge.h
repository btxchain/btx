// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SENDEREDGE_H
#define BTX_MODELNET_SWARM_SENDEREDGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one sender edge of an invoice. hop is the
 * caller-supplied hop index. sender_owned says the edge belongs to the
 * sender. want_fee asks this note to add a fee. want_cltv asks this note
 * to add a CLTV.
 *
 * This note does not route and does not broadcast. fee_atoms stays 0 and
 * cltv_added stays false on every path. No hostnames or IPs are used.
 */
struct SwarmSenderEdge {
    std::string invoice_id;
    int64_t hop{0};
    bool sender_owned{false};
    bool want_fee{false};
    bool want_cltv{false};
};

/**
 * Outcome of noting a sender edge. fee_atoms stays 0 and cltv_added stays
 * false: the sender's own first edge adds no fee and no CLTV. Nothing is
 * routed and nothing is broadcast.
 */
struct SwarmSenderEdgeResult {
    int64_t fee_atoms{0};
    bool cltv_added{false};
    std::string code;
};

/**
 * Note a sender edge without adding a fee or a CLTV.
 * Order, first match wins: an empty invoice_id or hop below 1 is EDGE.
 * hop other than 1, or an edge that is not sender-owned, is NOT_FIRST.
 * That wins even when want_fee or want_cltv is true. want_fee is NO_FEE.
 * The sender's own first edge adds no fee. That wins even when want_cltv
 * is true. want_cltv is NO_CLTV. Otherwise the note is NOTED and err is
 * clear. fee_atoms stays 0 and cltv_added stays false on every path.
 * Nothing is routed and nothing is broadcast.
 */
SwarmSenderEdgeResult SwarmNoteSenderEdge(const SwarmSenderEdge& edge, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SENDEREDGE_H
