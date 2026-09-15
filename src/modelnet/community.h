// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_COMMUNITY_H
#define BITCOIN_MODELNET_COMMUNITY_H

#include <univalue.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * V11-COMM-06: following a collection is preview-only.
 *
 * Reports estimated disk/egress against the already-approved quota. Never
 * raises storage_quota_bytes. Automatic preservation stays off until the
 * operator separately enables it within that budget.
 */
UniValue CollectionFollowImpactPreview(uint64_t quota_bytes,
                                       uint64_t used_bytes,
                                       uint64_t estimated_disk_bytes,
                                       uint64_t estimated_egress_bytes);

/** True when estimated_disk_bytes fits in remaining quota (used <= quota). */
bool CollectionFollowWithinBudget(uint64_t quota_bytes,
                                    uint64_t used_bytes,
                                    uint64_t estimated_disk_bytes);

} // namespace modelnet

#endif // BITCOIN_MODELNET_COMMUNITY_H
