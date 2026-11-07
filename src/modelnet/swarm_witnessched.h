// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WITNESSCHED_H
#define BTX_MODELNET_SWARM_WITNESSCHED_H

#include <map>
#include <string>

namespace modelnet {

/** A scheduler never signs a funding witness. */
class SwarmWitnessSched {
public:
    bool Record(const std::string& txid, bool scheduler, bool covers_outputs, std::string& err);
    bool signed_ok(const std::string& txid) const;

private:
    std::map<std::string, bool> m_stored;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WITNESSCHED_H
