// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_CHANNEL_H
#define BITCOIN_MODELNET_SWARM_GENERATION_CHANNEL_H

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

/**
 * Release channels. general/stable and code/stable are distinct heads.
 * follow writes the staged head only. pin and refuse leave both heads.
 */
class SwarmGenerationChannels {
public:
    const std::string& staged(const std::string& channel) const;
    const std::string& active(const std::string& channel) const;
    bool has_staged(const std::string& channel) const;
    void note_policy(const std::string& channel, const std::string& policy);
    void stage_follow(const std::string& channel, const std::string& candidate_id);
    bool adopt(const std::string& channel, std::string& previous, std::string& adopted);
    std::vector<std::pair<std::string, std::string>> actives() const;

private:
    struct Head {
        std::string staged;
        std::string active;
        std::string policy;
    };
    std::map<std::string, Head> m_heads;
    std::string m_blank;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_CHANNEL_H
