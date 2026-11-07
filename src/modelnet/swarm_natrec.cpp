// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#include <modelnet/swarm_natrec.h>

#include <string>

namespace modelnet {

SwarmNatRecResult SwarmRecordNat(const SwarmNatRec& rec, std::string& err)
{
    // A NAT record does not publish an address or open a socket.
    SwarmNatRecResult result;
    result.published = false;
    result.opened = false;
    if (rec.node_id.empty()) {
        result.code = "NODE";
        result.published = false;
        result.opened = false;
        err = "NODE";
        return result;
    }
    if (rec.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.opened = false;
        err = "HELD";
        return result;
    }
    if (rec.want_open) {
        result.code = "HELD";
        result.published = false;
        result.opened = false;
        err = "HELD";
        return result;
    }
    if (rec.mapped) {
        result.code = "NOTED";
        result.published = false;
        result.opened = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
