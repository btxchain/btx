// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_TABLE_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_TABLE_H

#include <modelnet/swarm_nicheslots/record.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Independent rows keyed by niche name.
 * Open inserts one row. Spend decrements and appends only on that row.
 * A missing niche stays missing: remaining is -1 and the task list is empty.
 */
class SwarmNicheSlotsTable {
public:
    bool opened(const std::string& niche) const;
    int64_t remaining(const std::string& niche) const;
    bool has_task(const std::string& niche, const std::string& task) const;
    std::vector<std::string> tasks(const std::string& niche) const;

    /** Insert a row. A niche that is already present is left unchanged. */
    void Open(const std::string& niche, int64_t slots);

    /**
     * Decrement this niche and append the task.
     * No row, a spent task, or a remaining of 0 leaves the table as it was.
     */
    void Spend(const std::string& niche, const std::string& task);

private:
    std::map<std::string, SwarmNicheSlotsRecord> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_TABLE_H
