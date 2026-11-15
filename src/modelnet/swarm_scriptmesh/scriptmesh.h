// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_H

#include <modelnet/swarm_scriptmesh/policy.h>
#include <modelnet/swarm_scriptmesh/replay.h>
#include <modelnet/swarm_scriptmesh/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Multi-hop claim-leaf plane.
 * AddHop stores a hop when the hash is 32 bytes, the claimant is an
 * ML-DSA-44 key, and the expiry is at least 160 above the previous hop.
 * Build writes one SHA-256 claim leaf per stored hop and parses it back.
 * Each leaf pins the preimage length. On success scripts_ok() is true,
 * qualified() stays false, code() is UNQUALIFIED, and secp_penalty() stays
 * false. The built leaves stay unsettled.
 * A later Build of the same hops is REPLAY and does not append leaves.
 * RefundLeaf writes one refund leaf for the last hop.
 * bytes_moved() stays 0. broadcast() stays false.
 */
class SwarmScriptMesh {
public:
    /** Fewer than claimant, hash, and expiry. PREIMAGE. Stores nothing. */
    bool AddHop();
    /** Hash and expiry absent. PREIMAGE. Stores nothing. */
    bool AddHop(const std::vector<unsigned char>& claimant_pubkey);
    /** Expiry absent. PREIMAGE. Stores nothing. */
    bool AddHop(const std::vector<unsigned char>& claimant_pubkey,
                const std::vector<unsigned char>& hash);
    /**
     * Store one hop.
     * A hash whose size is not 32 is PREIMAGE.
     * An empty claimant, or a claimant whose size is not MLDSA44_PUBKEY_SIZE,
     * is KEY. An expiry under 160 above the previous hop is TIMEOUT.
     */
    bool AddHop(const std::vector<unsigned char>& claimant_pubkey,
                const std::vector<unsigned char>& hash,
                int64_t expiry);

    /**
     * Build one claim leaf per stored hop. Requires at least two hops.
     * Success sets scripts_ok and code UNQUALIFIED. qualified stays false.
     * The same hops again are REPLAY.
     */
    bool Build();

    /** One refund leaf for the last stored hop. broadcast stays false. */
    bool RefundLeaf();

    bool scripts_ok() const { return m_scripts_ok; }
    bool qualified() const { return m_policy.qualified(); }
    const std::string& code() const { return m_code; }
    bool secp_penalty() const { return m_policy.secp_penalty(); }
    int64_t bytes_moved() const { return m_policy.bytes_moved(); }
    bool broadcast() const { return m_policy.broadcast(); }

    std::size_t hop_count() const { return m_hops.size(); }
    const std::vector<SwarmScriptMeshHop>& hops() const { return m_hops; }
    const std::vector<std::vector<unsigned char>>& claim_leaves() const { return m_claim_leaves; }
    const std::vector<unsigned char>& refund_leaf() const { return m_refund; }

private:
    bool RejectIncomplete(const std::vector<unsigned char>& claimant,
                          const std::vector<unsigned char>& hash,
                          int64_t expiry);

    std::vector<SwarmScriptMeshHop> m_hops;
    std::vector<std::vector<unsigned char>> m_claim_leaves;
    std::vector<unsigned char> m_refund;
    SwarmScriptMeshReplay m_replay;
    SwarmScriptMeshPolicy m_policy;
    bool m_scripts_ok{false};
    std::string m_code;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_H
