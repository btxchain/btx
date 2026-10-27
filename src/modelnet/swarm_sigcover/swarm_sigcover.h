// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_H

#include <modelnet/swarm_sigcover/codes.h>
#include <modelnet/swarm_sigcover/flags.h>
#include <modelnet/swarm_sigcover/ledger.h>
#include <modelnet/swarm_sigcover/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process signature-cover book.
 * Cover records whether a sighash description covered outputs, and a later
 * false description leaves that record covered.
 * Preimage records that a 32-byte preimage was described. Any other length
 * stores nothing. The description does not make Claim succeed.
 * BindKey attaches no key. Claim stays unqualified. Penalty stores nothing.
 * signed_ok() stays false. secp_penalty() stays false. broadcast() stays false.
 * launched() stays false. gpu() stays false. atoms_moved() stays 0.
 * automatic_spend() stays "0".
 * This book does not attach a key, sign, broadcast, claim coins, or apply a
 * secp256k1 penalty. There is no method that flips the frozen inspectors.
 */
class SwarmSigCover {
public:
    /**
     * Empty id is SIGHASH and stores nothing.
     * The first call with covers_outputs false is NOT_SIGNED and stores nothing.
     * The first call with covers_outputs true stores the id as covered and returns true.
     * signed_ok() stays false.
     * A later call with covers_outputs false is NOT_SIGNED and does not clear the covered record.
     * A later call with covers_outputs true for an already covered id is REPLAY and keeps the record.
     */
    bool Cover(const std::string& id, bool covers_outputs, std::string& err);

    /**
     * Empty id is SIGHASH and stores nothing.
     * length other than 32 is PREIMAGE and stores nothing.
     * length 32 stores that a 32-byte preimage was described and returns true.
     * That store does not make Claim succeed.
     * A second length-32 description of the same id is REPLAY.
     */
    bool Preimage(const std::string& id, int64_t length, std::string& err);

    /**
     * Empty id is SIGHASH and stores nothing.
     * Any key, including an empty key, returns false with NOT_SIGNED and stores no key.
     * signed_ok() stays false. An existing covered record stays covered.
     */
    bool BindKey(const std::string& id, const std::string& key, std::string& err);

    /**
     * Always false with UNQUALIFIED.
     * atoms_moved() stays 0. broadcast() stays false.
     * A covered id and a 32-byte preimage description do not change this.
     */
    bool Claim(const std::string& id, std::string& err);

    /**
     * Always false with NOT_PENALTY.
     * secp_penalty() stays false. Nothing is stored.
     */
    bool Penalty(const std::string& id, std::string& err);

    /** True when Cover stored this id as covered. */
    bool covered(const std::string& id) const;

    /** 32 when a 32-byte preimage description is stored, otherwise -1. */
    int preimage_len(const std::string& id) const;

    bool signed_ok() const;
    bool secp_penalty() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;

private:
    SwarmSigCoverLedger m_ledger;
    SwarmSigCoverFlags m_flags;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_H
