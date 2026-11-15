// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_LEDGER_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_LEDGER_H

#include <modelnet/swarm_routebook/types.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory hop margins keyed by route id.
 * A route enters the map only when AddHop appends a hop.
 * A failed add leaves the map unchanged.
 */
class SwarmRouteBookLedger {
public:
    /**
     * Empty route or empty hop is ROUTE and stores nothing.
     * cltv_expiry below 0 on a new hop is EXPIRY and stores nothing.
     * A second add of the same route and hop is REPLAY and keeps the first expiry.
     * Otherwise the hop is appended.
     */
    bool AddHop(const std::string& route, const std::string& hop, int64_t cltv_expiry, std::string& err);

    /** True when AddHop has stored at least one hop for route. */
    bool known(const std::string& route) const;

    /** Stored hops. An unknown route is 0. */
    int64_t hop_count(const std::string& route) const;

    /** hop_count times the close margin. An unknown route is 0. */
    int64_t required_slack(const std::string& route) const;

    /**
     * Stored upstream delta. An unknown route, and a route whose delta
     * was not stored, returns 0.
     */
    int64_t bound_delta(const std::string& route) const;

    /**
     * First stored expiry. Returns false when the route or hop is absent
     * and leaves expiry unchanged.
     */
    bool cltv_expiry(const std::string& route, const std::string& hop, int64_t& expiry) const;

    /** True when a covering sighash description is stored for route. */
    bool outputs_covered(const std::string& route) const;

    SwarmRouteBookPath* Find(const std::string& route);
    const SwarmRouteBookPath* Find(const std::string& route) const;

private:
    std::map<std::string, SwarmRouteBookPath> m_paths;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_LEDGER_H
