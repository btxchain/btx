// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_GRANT_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_GRANT_H

#include <modelnet/swarm_leasework/book.h>
#include <modelnet/swarm_leasework/epoch.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Grant one task to one worker at the current epoch.
 * Order, first match wins: an empty task or worker is TASK. A negative
 * bound is RANGE. until_ms < now_ms is EXPIRED and stores nothing.
 * until_ms >= now_ms is inside the lease. A task already stored is REPLAY
 * and keeps the first worker.
 */
bool LeaseWorkGrant(LeaseWorkBook& book, const LeaseWorkEpoch& epoch, const std::string& task,
                    const std::string& worker, int64_t now_ms, int64_t until_ms, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_GRANT_H
