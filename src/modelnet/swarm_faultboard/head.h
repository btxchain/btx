// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_HEAD_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_HEAD_H

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Active head per channel, plus appended rollbacks.
 * Keep replaces the active head for that channel.
 * Restore sets the active head to previous and appends one rollback.
 * There is no erase of a head or a rollback.
 */
class SwarmFaultHeadBook {
public:
    bool Keep(const std::string& channel, const std::string& head, std::string& err);
    std::string head_for(const std::string& channel) const;
    void Restore(const std::string& channel, const std::string& previous);
    std::size_t rollback_count() const;

private:
    struct Rollback {
        std::string channel;
        std::string from_head;
        std::string to_head;
    };

    std::map<std::string, std::string> m_heads;
    std::vector<Rollback> m_rollbacks;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_HEAD_H
