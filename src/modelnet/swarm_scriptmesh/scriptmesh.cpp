// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/scriptmesh.h>

#include <modelnet/swarm_scriptmesh/admit.h>
#include <modelnet/swarm_scriptmesh/claim.h>
#include <modelnet/swarm_scriptmesh/refund.h>

#include <utility>

namespace modelnet {

bool SwarmScriptMesh::RejectIncomplete(const std::vector<unsigned char>& claimant,
                                       const std::vector<unsigned char>& hash,
                                       int64_t expiry)
{
    std::string code;
    SwarmScriptMeshAdmitHop(m_hops, claimant, hash, expiry, /*fields_complete=*/false, code);
    m_code = code.empty() ? std::string(kSwarmScriptMeshPreimage) : code;
    return false;
}

bool SwarmScriptMesh::AddHop()
{
    return RejectIncomplete({}, {}, 0);
}

bool SwarmScriptMesh::AddHop(const std::vector<unsigned char>& claimant_pubkey)
{
    return RejectIncomplete(claimant_pubkey, {}, 0);
}

bool SwarmScriptMesh::AddHop(const std::vector<unsigned char>& claimant_pubkey,
                             const std::vector<unsigned char>& hash)
{
    return RejectIncomplete(claimant_pubkey, hash, 0);
}

bool SwarmScriptMesh::AddHop(const std::vector<unsigned char>& claimant_pubkey,
                             const std::vector<unsigned char>& hash,
                             int64_t expiry)
{
    std::string code;
    if (!SwarmScriptMeshAdmitHop(m_hops, claimant_pubkey, hash, expiry, /*fields_complete=*/true, code)) {
        m_code = code;
        return false;
    }
    m_hops.push_back(SwarmScriptMeshHop{claimant_pubkey, hash, expiry});
    m_claim_leaves.clear();
    m_refund.clear();
    m_scripts_ok = false;
    m_replay.Forget();
    m_code.clear();
    return true;
}

bool SwarmScriptMesh::Build()
{
    if (m_hops.size() < 2) {
        m_code = kSwarmScriptMeshHops;
        return false;
    }
    if (m_replay.Same(m_hops)) {
        m_code = kSwarmScriptMeshReplay;
        return false;
    }

    std::vector<std::vector<unsigned char>> leaves;
    leaves.reserve(m_hops.size());
    for (const SwarmScriptMeshHop& hop : m_hops) {
        std::vector<unsigned char> script;
        std::string code;
        if (!SwarmScriptMeshClaimLeaf(hop, script, code)) {
            m_code = code.empty() ? std::string(kSwarmScriptMeshScript) : code;
            return false;
        }
        leaves.push_back(std::move(script));
    }

    m_claim_leaves = std::move(leaves);
    m_replay.Remember(m_hops);
    m_scripts_ok = true;
    m_code = kSwarmScriptMeshUnqualified;
    return true;
}

bool SwarmScriptMesh::RefundLeaf()
{
    if (m_hops.empty()) {
        m_code = kSwarmScriptMeshHops;
        return false;
    }

    std::vector<unsigned char> script;
    std::string code;
    if (!SwarmScriptMeshMakeRefundLeaf(m_hops.back(), script, code)) {
        m_code = code.empty() ? std::string(kSwarmScriptMeshScript) : code;
        return false;
    }

    m_refund = std::move(script);
    m_code = kSwarmScriptMeshUnqualified;
    return true;
}

} // namespace modelnet
