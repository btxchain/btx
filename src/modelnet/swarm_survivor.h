// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SURVIVOR_H
#define BTX_MODELNET_SWARM_SURVIVOR_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local durable commitment set. coordinator_id names who committed or who
 * is reading. The log is the durable set, not owned by one process. A
 * different coordinator_id does not erase rows.
 *
 * This is a local record of durable commitments. It does not open a
 * socket, broadcast, name a host, or use an address. Read is not a killed
 * process and not a cluster election.
 *
 * Commit codes: DURABLE, STALE, CONFLICT. Read codes: DURABLE, EMPTY, STALE.
 * Success clears err. Read sets continues true only when it returns the
 * stored commitment ids.
 */
class SwarmDurableLog {
public:
    bool Commit(const std::string& coordinator_id, int64_t epoch, const std::string& commitment_id,
                const std::string& body, std::string& err);
    bool Read(const std::string& coordinator_id, int64_t epoch, std::vector<std::string>& commitment_ids,
              bool& continues, std::string& err) const;
    int Count() const;

private:
    struct Record {
        std::string body;
        int64_t epoch{0};
    };
    std::map<std::string, Record> m_rows; // commitment_id -> record
    int64_t m_epoch{0}; // highest accepted epoch, 0 if none
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SURVIVOR_H
