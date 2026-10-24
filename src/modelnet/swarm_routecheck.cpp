// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routecheck.h>

namespace modelnet {
namespace {

SwarmRouteResult Finish(const std::string& code, std::string& err, bool classified)
{
    SwarmRouteResult result;
    result.qualified = false;
    result.secp_penalty = false;
    result.code = code;
    if (classified) {
        err.clear();
    } else {
        err = code;
    }
    return result;
}

} // namespace

SwarmRouteResult SwarmCheckRoute(const SwarmRouteRequest& request, std::string& err)
{
    if (request.hops < 1) {
        return Finish("ROUTE", err, false);
    }
    if (request.preimage_len != 32) {
        return Finish("PREIMAGE", err, false);
    }
    if (request.hops == 1 && request.lifetime_ok && request.liquidity_reserved) {
        return Finish("DIRECT", err, true);
    }
    if (request.hops > 1 && !request.cltv_staggered) {
        return Finish("STAGGER", err, false);
    }
    if (request.hops > 1 && !request.lifetime_ok) {
        return Finish("LIFETIME", err, false);
    }
    if (request.hops > 1 && !request.liquidity_reserved) {
        return Finish("LIQUIDITY", err, false);
    }
    if (request.hops > 1) {
        return Finish("UNQUALIFIED", err, true);
    }
    if (!request.lifetime_ok) {
        return Finish("LIFETIME", err, false);
    }
    return Finish("LIQUIDITY", err, false);
}

} // namespace modelnet
