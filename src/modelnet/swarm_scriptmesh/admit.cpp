// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/admit.h>

#include <pqkey.h>

#include <limits>

namespace modelnet {

namespace {

bool ExpiryRises(int64_t previous, int64_t expiry)
{
    if (previous > std::numeric_limits<int64_t>::max() - kSwarmScriptMeshExpiryRise) {
        return false;
    }
    return expiry >= previous + kSwarmScriptMeshExpiryRise;
}

} // namespace

bool SwarmScriptMeshAdmitHop(const std::vector<SwarmScriptMeshHop>& stored,
                             const std::vector<unsigned char>& claimant,
                             const std::vector<unsigned char>& hash,
                             int64_t expiry,
                             bool fields_complete,
                             std::string& code)
{
    if (!fields_complete || hash.size() != kSwarmScriptMeshHashSize) {
        code = kSwarmScriptMeshPreimage;
        return false;
    }
    if (claimant.empty() || claimant.size() != MLDSA44_PUBKEY_SIZE) {
        code = kSwarmScriptMeshKey;
        return false;
    }
    if (!stored.empty() && !ExpiryRises(stored.back().expiry, expiry)) {
        code = kSwarmScriptMeshTimeout;
        return false;
    }
    code.clear();
    return true;
}

} // namespace modelnet
