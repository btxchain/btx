// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_CERTIFICATE_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_CERTIFICATE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Promotion certificate for one candidate.
 * A certificate is not money. money, realm_promoted, and
 * exact_replay_admitted stay false. The certificate does not spend,
 * broadcast, or admit exact replay.
 */
struct SwarmEvaluationCertificate {
    std::string candidate;
    bool money{false};
    bool realm_promoted{false};
    bool exact_replay_admitted{false};
};

/**
 * Certificates keyed by candidate.
 * store writes one certificate with money, realm, and exact replay
 * all false. A second store keeps the first. There is no erase.
 * Storing a certificate does not remove regression reports.
 */
class SwarmEvaluationCertificateBook {
public:
    bool contains(const std::string& candidate) const;
    bool money(const std::string& candidate) const;
    bool realm_promoted(const std::string& candidate) const;
    bool exact_replay_admitted(const std::string& candidate) const;
    bool store(const std::string& candidate);

private:
    std::map<std::string, SwarmEvaluationCertificate> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_CERTIFICATE_H
