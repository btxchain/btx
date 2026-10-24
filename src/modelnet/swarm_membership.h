// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MEMBERSHIP_H
#define BITCOIN_MODELNET_SWARM_MEMBERSHIP_H

#include <set>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmBinding {
    std::string principal;
    std::string realm;
    std::string role;
    int64_t expiry{0};
    bool revoked{false};
    bool spend_key_present{false};
};

bool SwarmAuthorize(const SwarmBinding& binding, int64_t now_ms, const std::string& required_role, std::string& err);

bool SwarmAcceptInvitation(std::set<std::string>& seen_nonces, const std::string& recipient, const std::string& nonce,
                           bool worker_announcement, bool claims_voter, std::string& err);

bool SwarmCommitteeUnchanged(const std::vector<std::string>& current, const std::vector<std::string>& proposed);

struct SwarmPublication {
    bool quality_graduated{false};
    bool realm_promoted{false};
    bool exact_replay_admitted{false};
};

SwarmPublication SwarmPublishGraduation(bool quality_passed);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MEMBERSHIP_H
