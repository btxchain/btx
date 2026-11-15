// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_ELECTION_H
#define BITCOIN_MODELNET_SWARM_FORM_ELECTION_H

#include <modelnet/swarm_form/membership.h>

#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Coordinator election over members already admitted.
 * The epoch starts at 1. An empty candidate is LEADER and stores nothing.
 * A candidate that has not been admitted is NOT_ADMITTED and stores nothing.
 * An epoch older than the current epoch is STALE_EPOCH and does not replace the leader.
 * The same epoch does not replace a leader already stored.
 */
class SwarmFormElection {
public:
    bool Load(const fs::path& swarm_dir, std::string& err);
    bool Claim(const fs::path& swarm_dir, const SwarmFormMembership& members, const std::string& candidate, uint64_t epoch, std::string& err);
    const std::string& leader() const { return m_leader; }
    uint64_t epoch() const { return m_epoch; }

private:
    bool Save(const fs::path& swarm_dir, std::string& err);
    fs::path m_dir;
    std::string m_leader;
    uint64_t m_epoch{1};
    bool m_loaded{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_ELECTION_H
