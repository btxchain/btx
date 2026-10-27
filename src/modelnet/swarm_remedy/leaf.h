// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_LEAF_H
#define BITCOIN_MODELNET_SWARM_REMEDY_LEAF_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Local remedy script. Built by SwarmRemedyScript and kept in this object.
 * An empty hash or pubkey is KEY and leaves the stored script unchanged.
 * The script is not broadcast.
 */
class SwarmRemedyLeaf {
public:
    std::vector<unsigned char> Store(const std::vector<unsigned char>& secret_hash,
                                     const std::vector<unsigned char>& counterparty_pubkey, std::string& err);
    const std::vector<unsigned char>& script() const { return m_script; }

private:
    std::vector<unsigned char> m_script;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_LEAF_H
