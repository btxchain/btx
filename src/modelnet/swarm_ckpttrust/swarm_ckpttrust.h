// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_SWARM_CKPTTRUST_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_SWARM_CKPTTRUST_H

#include <modelnet/swarm_ckpttrust/book.h>
#include <modelnet/swarm_ckpttrust/quiet.h>
#include <modelnet/swarm_ckpttrust/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Checkpoint trust plane.
 * A checkpoint claim is recorded and is not lineage authority.
 *
 * Trust stores a non-empty claim and returns false. err is NOT_TRUST.
 * trusted() stays false.
 * An empty claim is CLAIM and stores nothing.
 * A second Trust of the same claim is REPLAY and keeps the first.
 * CLAIM is decided before REPLAY. REPLAY is decided before NOT_TRUST.
 * A checkpoint-only claim is not lineage authority.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 * There is no method that sets trusted() true.
 */
class SwarmCheckpointTrust {
public:
    /**
     * Record one checkpoint claim.
     * An empty claim is CLAIM and stores nothing.
     * A non-empty claim is stored and the call returns false. err is NOT_TRUST.
     * A second Trust of the same claim is REPLAY and keeps the first.
     * trusted() stays false.
     * A checkpoint-only claim is not lineage authority.
     */
    bool Trust(const std::string& claim, std::string& err);

    /** True when Trust kept this claim. */
    bool claimed(const std::string& claim) const;

    /** The kept claim, or empty when it was not stored. */
    std::string stored_claim(const std::string& claim) const;

    /** Number of kept claims. */
    std::size_t claim_count() const;

    /** Stays false. A recorded claim is not lineage authority. */
    bool trusted() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmCheckpointTrustBook m_book;
    SwarmCheckpointTrustQuiet m_quiet;
    SwarmCheckpointTrustStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_SWARM_CKPTTRUST_H
