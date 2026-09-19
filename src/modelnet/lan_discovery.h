// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAN_DISCOVERY_H
#define BITCOIN_MODELNET_LAN_DISCOVERY_H

#include <string>

namespace modelnet {

/** RFC1918 / link-local / .local observation. Not a consensus role. */
bool EndpointLooksLan(const std::string& endpoint);
/** Prefer a LAN peer over a WAN peer for the same resource when both are fresh. */
bool PreferLanPeer(const std::string& candidate, const std::string& other);
bool DelegatedRoutingMutatesConsensus();
bool LanDiscoveryRequiresPublicAddress();

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAN_DISCOVERY_H
