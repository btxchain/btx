// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CKPTTRUST_H
#define BTX_MODELNET_SWARM_CKPTTRUST_H

#include <map>
#include <string>

namespace modelnet {

/** A checkpoint id alone is not lineage trust. Trust requires the checkpoint, a recipe, and a bound dataset. */
class SwarmCkptTrust {
public:
    bool Claim(const std::string& checkpoint, bool recipe_present, bool dataset_bound, std::string& err);
    bool trusted(const std::string& checkpoint) const;
    bool bytes_moved() const;

private:
    std::map<std::string, bool> m_stored;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CKPTTRUST_H
