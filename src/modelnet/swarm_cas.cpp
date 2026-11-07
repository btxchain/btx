// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cas.h>

namespace modelnet {

bool SwarmCommitCas(SwarmCasPlan& plan, bool want_delete_orphan, std::string& err)
{
    if (!plan.eviction_valid) {
        plan.index_committed = false;
        plan.orphan_deleted = false;
        plan.bytes_trusted = false;
        err = "EVICTION";
        return false;
    }
    plan.index_committed = true;
    plan.bytes_trusted = false;
    plan.orphan_deleted = want_delete_orphan;
    err.clear();
    return true;
}

bool SwarmTrustIncomplete(bool digest_verified, std::string& err)
{
    if (!digest_verified) {
        err = "INCOMPLETE";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
