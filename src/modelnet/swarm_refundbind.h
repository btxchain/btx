// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REFUNDBIND_H
#define BTX_MODELNET_SWARM_REFUNDBIND_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmRefundBind {
    std::string channel_id;
    bool signer{false};
    bool want_bind{false};
    bool want_broadcast{false};
};

struct SwarmRefundBindResult {
    std::string code;
    bool bound{false};
    bool broadcast{false};
    int64_t atoms{0};
};

/** A refund bind record does not bind a leaf and does not broadcast. */
SwarmRefundBindResult SwarmBindRefundLocal(const SwarmRefundBind& bind, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REFUNDBIND_H
