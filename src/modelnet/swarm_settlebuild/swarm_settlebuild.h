// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_H

#include <modelnet/swarm_settlebuild/flags.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory HTLC leaf builder.
 * BuildClaim stores one SHA-256 claim leaf for an ML-DSA-44 claimant key.
 * BuildRefund stores one refund leaf for an ML-DSA-44 sender key.
 * The leaves are script bytes held in this object.
 * Settle returns UNQUALIFIED. qualified() stays false.
 * broadcast() stays false. launched() stays false. gpu() stays false.
 * atoms_moved() stays 0. automatic_spend() stays "0". secp_penalty() stays false.
 * There is no method that sets qualified() true.
 * This plane does not broadcast, mine, or move atoms.
 */
class SwarmSettleBuild {
public:
    /**
     * Payment hash size other than 32 is PREIMAGE and stores nothing.
     * An empty pubkey, or a pubkey whose size is not the ML-DSA-44 size, is KEY
     * and stores nothing. The leaf builder is not called for those inputs.
     * Otherwise the claim leaf is stored when it parses back to the same hash
     * and pubkey and the preimage length pin holds.
     * A parse miss is SCRIPT and stores nothing. qualified() stays false.
     */
    bool BuildClaim(const std::vector<unsigned char>& payment_hash,
                    const std::vector<unsigned char>& pubkey,
                    std::string& err);

    /**
     * Timeout below 1 is TIMEOUT and stores nothing.
     * A bad pubkey is KEY and stores nothing. The leaf builder is not called
     * for those inputs.
     * Otherwise the refund leaf is stored when it parses back to the same
     * timeout and pubkey. A parse miss is SCRIPT and stores nothing.
     */
    bool BuildRefund(int64_t timeout, const std::vector<unsigned char>& pubkey, std::string& err);

    /**
     * Always false with UNQUALIFIED.
     * atoms_moved() stays 0. broadcast() stays false.
     * A stored claim script does not change this.
     */
    bool Settle(std::string& err);

    bool has_claim() const;
    bool has_refund() const;
    const std::vector<unsigned char>& claim_script() const;
    const std::vector<unsigned char>& refund_script() const;
    bool qualified() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool secp_penalty() const;

private:
    std::vector<unsigned char> m_claim;
    std::vector<unsigned char> m_refund;
    SwarmSettleBuildFlags m_flags;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_H
