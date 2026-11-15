// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REVOKEGATE_H
#define BTX_MODELNET_SWARM_REVOKEGATE_H

#include <string>

namespace modelnet {

/**
 * A later cache read composed with revocation. This is a composed check.
 * It is not a live cache. plaintext_erased and bytes_moved stay false:
 * the function does not erase plaintext and does not move bytes.
 */
struct SwarmRevokeGateResult {
    bool allowed{false};
    bool plaintext_erased{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Order: a previously delivered page is DELIVERED_KEPT and is not a new read
 * (err is clear). A revoked member is REVOKED. A different tenant or an
 * unauthorized caller is TENANT. Otherwise the read is OK. Previously
 * delivered plaintext is kept. This function does not erase plaintext and
 * does not move bytes.
 */
SwarmRevokeGateResult SwarmReadAfterRevoke(bool member_revoked, bool previously_delivered, bool same_tenant,
                                           bool authorized, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REVOKEGATE_H
