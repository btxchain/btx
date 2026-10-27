// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_OBLIGATIONS_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_OBLIGATIONS_H

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Leases and earned rows. A lease is keyed by pool id and work id.
 * Work-payment marks the row earned and does not spend.
 * Profit-share is refused. Obligations stay on the pool id they were stored under.
 */
class SwarmPayObligations {
public:
    bool Lease(const std::string& pool, const std::string& work, const std::string& worker, std::string& err);
    bool Pay(const std::string& pool, const std::string& work, const std::string& label, std::string& err);

    bool leased(const std::string& pool, const std::string& work) const;
    bool earned(const std::string& pool, const std::string& work) const;
    int64_t earned_count() const;
    std::string worker(const std::string& pool, const std::string& work) const;

private:
    struct Row {
        std::string worker;
        bool earned{false};
    };

    std::map<std::pair<std::string, std::string>, Row> m_rows;
    int64_t m_earned{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_OBLIGATIONS_H
