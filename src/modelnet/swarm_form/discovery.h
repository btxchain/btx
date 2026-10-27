// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_DISCOVERY_H
#define BITCOIN_MODELNET_SWARM_FORM_DISCOVERY_H

#include <modelnet/swarm_form/membership.h>

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Admit a peer id that presents this plane's family.
 * A peer that advertises compatibility without that family is FALSE_COMPAT and is not admitted.
 * A matching family is admitted. This class does not connect, open a socket, or record an address.
 */
class SwarmFormDiscovery {
public:
    bool Consider(const fs::path& swarm_dir, SwarmFormMembership& members, const std::string& peer_id, const std::string& family_id, bool advertises_compatibility, std::string& err);
    bool connects() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_DISCOVERY_H
