// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ROTGATE_H
#define BTX_MODELNET_SWARM_ROTGATE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * A fixed holdout is not rotating. Rotation is true only after two
 * different holdout ids have been accepted. Scores are not averaged
 * and nothing is published.
 */
class SwarmRotGate {
public:
    bool Record(const std::string& report, const std::string& holdout, bool rotating, std::string& err);
    bool rotated() const;
    int accepted() const;

private:
    std::map<std::string, std::string> m_stored;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ROTGATE_H
