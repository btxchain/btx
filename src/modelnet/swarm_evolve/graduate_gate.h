// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_GRADUATE_GATE_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_GRADUATE_GATE_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Graduation request. realm_promote asks for a realm promotion. */
struct SwarmEvolveGraduateRequest {
    bool realm_promote{false};
    bool safety_regression{false};
    bool broad_regression{false};
};

/**
 * Quality graduation for one generation.
 * Commits only when measure is accepted and SwarmSafetyAllowsGraduation
 * allows it. realm_promote returns REALM and does not graduate.
 * Realm promotion and ExactReplay admission stay false.
 */
class SwarmEvolveGraduate {
public:
    bool Commit(bool measure_accepted, const std::string& parent, const std::string& weights, uint64_t generation,
                const SwarmEvolveGraduateRequest& request, std::string& err);
    void Reset();

    bool Graduated() const { return m_graduated; }
    const std::string& Id() const { return m_id; }
    bool RealmPromoted() const { return m_realm_promoted; }
    bool ExactReplayAdmitted() const { return m_exact_replay_admitted; }

private:
    bool m_graduated{false};
    bool m_realm_promoted{false};
    bool m_exact_replay_admitted{false};
    std::string m_id;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_GRADUATE_GATE_H
