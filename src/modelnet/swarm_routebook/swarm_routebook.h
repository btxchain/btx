// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_H

#include <modelnet/swarm_routebook/codes.h>
#include <modelnet/swarm_routebook/flags.h>
#include <modelnet/swarm_routebook/ledger.h>
#include <modelnet/swarm_routebook/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process hop-margin book.
 * AddHop records a hop and its first cltv expiry. Bind stores an upstream
 * delta that meets hop_count * kSwarmRouteBookMargin. Hashlock refuses to
 * treat a hashlock as a settled route. Sighash can record that a description
 * covered outputs, and attaches no key. Claim stays unqualified.
 * qualified() stays false on every path. secp_penalty() stays false.
 * broadcast() stays false. launched() stays false. gpu() stays false.
 * atoms_moved() stays 0. automatic_spend() stays "0". signed_ok() stays false.
 * This book does not open a channel, broadcast a transaction, or move atoms.
 * It does not set any invoice book's MultiHopQualified flag.
 * There is no method that flips the frozen inspectors.
 */
class SwarmRouteBook {
public:
    /**
     * Empty route or empty hop is ROUTE and stores nothing.
     * cltv_expiry below 0 on a new hop is EXPIRY and stores nothing.
     * A second add of the same route and hop is REPLAY and keeps the first expiry.
     * Otherwise the hop is appended. Adding a hop does not qualify the route.
     */
    bool AddHop(const std::string& route, const std::string& hop, int64_t cltv_expiry, std::string& err);

    /**
     * Unknown route is ROUTE.
     * upstream_delta below hop_count * 160 is SLACK and does not store the delta.
     * upstream_delta greater than or equal to the required slack stores the delta.
     * qualified() stays false either way.
     */
    bool Bind(const std::string& route, int64_t upstream_delta, std::string& err);

    /**
     * Unknown route is ROUTE.
     * preimage_len other than 32 is PREIMAGE and claims nothing.
     * preimage_len of 32 returns false with NOT_ROUTE.
     * qualified() stays false. A digest match is not a route.
     */
    bool Hashlock(const std::string& route, int64_t preimage_len, std::string& err);

    /**
     * Unknown route is ROUTE.
     * covers_outputs false is NOT_SIGNED and does not store a covering sighash.
     * covers_outputs true stores that the description covered outputs.
     * signed_ok() stays false. No key is attached.
     */
    bool Sighash(const std::string& route, bool covers_outputs, std::string& err);

    /**
     * Always false with UNQUALIFIED.
     * atoms_moved() stays 0. broadcast() stays false.
     * An unknown route is still UNQUALIFIED.
     */
    bool Claim(const std::string& route, std::string& err);

    /** Stored hops. An unknown route is 0. */
    int64_t hop_count(const std::string& route) const;

    /** hop_count * kSwarmRouteBookMargin. Zero hops require 0. */
    int64_t required_slack(const std::string& route) const;

    /** Stored upstream delta, or 0 when the delta was not stored. */
    int64_t bound_delta(const std::string& route) const;

    /**
     * First stored cltv expiry.
     * Returns false when the route or hop is absent and leaves expiry unchanged.
     */
    bool cltv_expiry(const std::string& route, const std::string& hop, int64_t& expiry) const;

    /** True when Sighash stored a description that covered outputs. */
    bool outputs_covered(const std::string& route) const;

    bool qualified() const;
    bool secp_penalty() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool signed_ok() const;

private:
    SwarmRouteBookLedger m_ledger;
    SwarmRouteBookFlags m_flags;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_H
