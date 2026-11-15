// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/cache.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

namespace {

bool RefuseBytes(const SwarmFaultQuiet& quiet, const char* code, std::string& err)
{
    const int64_t bytes = quiet.bytes_moved();
    (void)bytes;
    err = code;
    return false;
}

} // namespace

bool SwarmFaultCacheOwnerGone(const SwarmFaultQuiet& quiet, std::string& err)
{
    return RefuseBytes(quiet, kSwarmFaultHeld, err);
}

bool SwarmFaultTruncatedCache(const SwarmFaultQuiet& quiet, std::string& err)
{
    return RefuseBytes(quiet, kSwarmFaultIncomplete, err);
}

bool SwarmFaultPartialPiece(const SwarmFaultQuiet& quiet, std::string& err)
{
    return RefuseBytes(quiet, kSwarmFaultPiece, err);
}

bool SwarmFaultRevokedRead(const SwarmFaultQuiet& quiet, std::string& err)
{
    return RefuseBytes(quiet, kSwarmFaultNotRead, err);
}

} // namespace modelnet
