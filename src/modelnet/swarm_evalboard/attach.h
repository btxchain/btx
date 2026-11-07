// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_ATTACH_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_ATTACH_H

#include <set>
#include <string>

namespace modelnet {

/**
 * Attach records a subject only when it is accepted and not regressed.
 * Otherwise the call is ATTACH and the subject stays unattached.
 * Regress sets a flag, returns REGRESSION, and leaves any earlier
 * attachment in place. A later Attach on that subject returns REGRESSION.
 */
class SwarmEvalAttachGate {
public:
    bool Attach(const std::string& subject, bool accepted, std::string& err);
    bool Regress(const std::string& subject, std::string& err);

    bool attached(const std::string& subject) const;
    bool regressed(const std::string& subject) const;

private:
    std::set<std::string> m_attached;
    std::set<std::string> m_regressed;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_ATTACH_H
