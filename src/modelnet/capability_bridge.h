// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CAPABILITY_BRIDGE_H
#define BITCOIN_MODELNET_CAPABILITY_BRIDGE_H

#include <modelnet/action_authority.h>
#include <modelnet/capability.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Issue one ActionPermit for an effect listed on a LocalCapabilityGrant.
 * Expired grants, effects absent from grant.json["effects"], and an empty
 * grant_id fail with BTX035_PERMIT. ResearchMaySpend() stays false.
 * The issued permit is one-use: a second ActionGate::Consume fails BTX035_REPLAY.
 */
bool PermitFromGrant(const LocalCapabilityGrant& grant, const std::string& effect, const std::string& fingerprint,
                     int64_t now_ms, ActionPermit& out_permit, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CAPABILITY_BRIDGE_H
