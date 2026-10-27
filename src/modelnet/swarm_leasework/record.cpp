// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/record.h>

namespace modelnet {

LeaseWorkGrant LeaseWorkMakeGrant(const std::string& task, const std::string& worker, int64_t epoch, int64_t now_ms,
                                  int64_t until_ms)
{
    LeaseWorkGrant grant;
    grant.task = task;
    grant.worker = worker;
    grant.epoch = epoch;
    grant.now_ms = now_ms;
    grant.until_ms = until_ms;
    grant.committed = false;
    return grant;
}

} // namespace modelnet
