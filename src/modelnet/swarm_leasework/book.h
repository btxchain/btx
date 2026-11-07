// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_BOOK_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_BOOK_H

#include <modelnet/swarm_leasework/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Stored grants and the latest now_ms those grants observed.
 * Insert stores one task. A later insert of the same task is refused.
 * The observed clock moves forward only. A grant is live while its
 * until_ms is still at or after that clock.
 * There is no remove. The first result hash stays.
 */
class LeaseWorkBook {
public:
    bool contains(const std::string& task) const;
    std::string worker(const std::string& task) const;
    int64_t grant_epoch(const std::string& task) const;
    int64_t until_ms(const std::string& task) const;
    bool committed(const std::string& task) const;
    std::string result_hash(const std::string& task) const;
    bool holds(const std::string& worker) const;
    bool worker_live(const std::string& worker) const;
    int64_t observed_now() const;
    std::size_t size() const;

    /**
     * Store the grant at epoch.
     * Refuses a duplicate task. On refusal the book is unchanged.
     * On success the observed clock becomes max(observed, now_ms).
     */
    bool Insert(const std::string& task, const std::string& worker, int64_t epoch, int64_t now_ms, int64_t until_ms);

    /**
     * Store result_hash when the task exists and has no hash yet.
     * A second store is refused and the first hash stays.
     */
    bool StoreHash(const std::string& task, const std::string& result_hash);

private:
    std::map<std::string, LeaseWorkGrant> m_grants;
    int64_t m_observed_now{0};
    bool m_have_now{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_BOOK_H
