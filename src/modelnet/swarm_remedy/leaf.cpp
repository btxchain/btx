// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/leaf.h>

#include <modelnet/swarm_paymesh.h>
#include <modelnet/swarm_remedy/codes.h>

namespace modelnet {

std::vector<unsigned char> SwarmRemedyLeaf::Store(const std::vector<unsigned char>& secret_hash,
                                                  const std::vector<unsigned char>& counterparty_pubkey, std::string& err)
{
    const std::vector<unsigned char> built = SwarmRemedyScript(secret_hash, counterparty_pubkey);
    if (secret_hash.empty() || counterparty_pubkey.empty() || built.empty()) {
        err = kSwarmRemedyKey;
        return {};
    }
    m_script = built;
    err.clear();
    return m_script;
}

} // namespace modelnet
