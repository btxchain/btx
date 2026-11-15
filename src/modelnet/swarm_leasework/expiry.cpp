// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/expiry.h>

namespace modelnet {

bool LeaseWorkTimeOutOfRange(int64_t now_ms, int64_t until_ms)
{
    return now_ms < 0 || until_ms < 0;
}

bool LeaseWorkGrantExpired(int64_t now_ms, int64_t until_ms)
{
    return until_ms < now_ms;
}

bool LeaseWorkGrantLive(int64_t until_ms, int64_t now_ms)
{
    return until_ms >= now_ms;
}

} // namespace modelnet
