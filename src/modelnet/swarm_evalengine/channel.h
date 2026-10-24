// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_CHANNEL_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_CHANNEL_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Channel head.
 * active is the adopted candidate. staged is the follow candidate that
 * has not been adopted. pin and refuse record a policy and leave both
 * heads unchanged. follow writes staged and leaves active unchanged.
 */
struct SwarmEvaluationChannel {
    std::string channel;
    std::string active;
    std::string staged;
    std::string policy;
};

/**
 * Channel heads keyed by channel id.
 * set_staged writes the staged head and does not write active.
 * set_policy writes the policy and does not write either head.
 * adopt_staged moves staged onto active and clears staged.
 */
class SwarmEvaluationChannelBook {
public:
    std::string staged(const std::string& channel) const;
    std::string active(const std::string& channel) const;
    bool has_staged(const std::string& channel) const;
    void set_staged(const std::string& channel, const std::string& candidate);
    void set_policy(const std::string& channel, const std::string& policy);
    bool adopt_staged(const std::string& channel, std::string& previous, std::string& adopted);

private:
    std::map<std::string, SwarmEvaluationChannel> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_CHANNEL_H
