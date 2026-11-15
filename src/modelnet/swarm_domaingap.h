// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DOMAINGAP_H
#define BTX_MODELNET_SWARM_DOMAINGAP_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate across trust domains. candidate_id
 * names the candidate. domains is how many trust domains reported.
 * required_domains is the quorum size. outcomes_agree is whether those
 * reports agree.
 *
 * This is a local note. One trust domain is not a quorum, and agreement
 * is not graduation. No hostnames or IPs are used.
 */
struct SwarmDomainQuorum {
    std::string candidate_id;
    int domains{0};
    int required_domains{0};
    bool outcomes_agree{false};
};

/**
 * A local domain-quorum note. settled stays false on every path: one
 * trust domain is not a quorum, and agreement is not graduation.
 */
struct SwarmDomainQuorumResult {
    bool settled{false};
    std::string code;
};

/**
 * Note a domain quorum without settling or graduating a candidate.
 * Order, first match wins: an empty candidate_id, a domains below 1, or
 * a required_domains below 2 is QUORUM. domains below required_domains
 * is DOMAIN, including when outcomes_agree is true. Disagreement is
 * SPLIT. Otherwise the note is HELD and err is clear.
 * settled stays false on every path. One trust domain is not a quorum,
 * and agreement is not graduation. No hostnames or IPs are used.
 */
SwarmDomainQuorumResult SwarmNoteDomainQuorum(const SwarmDomainQuorum& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DOMAINGAP_H
