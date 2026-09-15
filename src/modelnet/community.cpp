// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/community.h>

#include <modelnet/cores.h>

namespace modelnet {

bool CollectionFollowWithinBudget(uint64_t quota_bytes,
                                  uint64_t used_bytes,
                                  uint64_t estimated_disk_bytes)
{
    if (CollectionFollowRaisesQuota()) return false;
    if (used_bytes > quota_bytes) return estimated_disk_bytes == 0;
    return estimated_disk_bytes <= (quota_bytes - used_bytes);
}

UniValue CollectionFollowImpactPreview(uint64_t quota_bytes,
                                       uint64_t used_bytes,
                                       uint64_t estimated_disk_bytes,
                                       uint64_t estimated_egress_bytes)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("preview_only", true);
    o.pushKV("quota_raised", false);
    o.pushKV("quota_bytes", quota_bytes);
    o.pushKV("used_bytes", used_bytes);
    o.pushKV("estimated_disk_bytes", estimated_disk_bytes);
    o.pushKV("estimated_egress_bytes", estimated_egress_bytes);
    o.pushKV("within_budget", CollectionFollowWithinBudget(quota_bytes, used_bytes, estimated_disk_bytes));
    o.pushKV("automatic_preservation", false);
    o.pushKV("note", "disk/egress preview only; subscribe does not raise quota or start fetch");
    return o;
}

} // namespace modelnet
