// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hopcheck.h>

#include <string>

namespace modelnet {

SwarmHopCheckResult SwarmCheckHopScript(const SwarmHopCheck& check, std::string& err)
{
    // A hop check can reject a bad description and still leaves settlement unqualified.
    SwarmHopCheckResult result;
    result.qualified = false;
    result.secp_penalty = false;
    result.hops = check.hops;
    if (check.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        result.secp_penalty = false;
        result.hops = check.hops;
        err = "ROUTE";
        return result;
    }
    if (check.preimage_len != 32) {
        result.code = "PREIMAGE";
        result.qualified = false;
        result.secp_penalty = false;
        result.hops = check.hops;
        err = "PREIMAGE";
        return result;
    }
    if (!check.covers_outputs) {
        result.code = "OUTPUTS";
        result.qualified = false;
        result.secp_penalty = false;
        result.hops = check.hops;
        err = "OUTPUTS";
        return result;
    }
    if (check.overlapping_timeout) {
        result.code = "TIMEOUT";
        result.qualified = false;
        result.secp_penalty = false;
        result.hops = check.hops;
        err = "TIMEOUT";
        return result;
    }
    if (!check.signer) {
        result.code = "SIGNER";
        result.qualified = false;
        result.secp_penalty = false;
        result.hops = check.hops;
        err = "SIGNER";
        return result;
    }
    if (check.hops < 2) {
        result.code = "HOPS";
        result.qualified = false;
        result.secp_penalty = false;
        result.hops = check.hops;
        err = "HOPS";
        return result;
    }
    // A well-formed description is still not a script-enforced settlement.
    result.code = "UNQUALIFIED";
    result.qualified = false;
    result.secp_penalty = false;
    result.hops = check.hops;
    err = "UNQUALIFIED";
    return result;
}

} // namespace modelnet
