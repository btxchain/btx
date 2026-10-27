// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_RECORD_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One stored grant.
 * epoch is the fence epoch at insert time. committed stays false until
 * the first result hash is stored. Nothing here launches a process.
 */
struct LeaseWorkGrant {
    std::string task;
    std::string worker;
    int64_t epoch{0};
    int64_t now_ms{0};
    int64_t until_ms{0};
    bool committed{false};
    std::string result_hash;
};

LeaseWorkGrant LeaseWorkMakeGrant(const std::string& task, const std::string& worker, int64_t epoch, int64_t now_ms,
                                  int64_t until_ms);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_RECORD_H
