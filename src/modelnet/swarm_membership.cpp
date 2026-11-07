// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_membership.h>

#include <algorithm>

namespace modelnet {

bool SwarmAuthorize(const SwarmBinding& binding, int64_t now_ms, const std::string& required_role, std::string& err)
{
    if (binding.spend_key_present) {
        err = "SPEND_KEY_FORBIDDEN";
        return false;
    }
    if (binding.principal.empty() || binding.realm.empty()) {
        err = "BINDING";
        return false;
    }
    if (binding.revoked) {
        err = "REVOKED";
        return false;
    }
    if (now_ms >= binding.expiry) {
        err = "EXPIRED";
        return false;
    }
    if (binding.role != required_role) {
        err = "ROLE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAcceptInvitation(std::set<std::string>& seen_nonces, const std::string& recipient, const std::string& nonce,
                           bool worker_announcement, bool claims_voter, std::string& err)
{
    if (recipient.empty() || nonce.empty()) {
        err = "INVITE";
        return false;
    }
    if (seen_nonces.count(nonce)) {
        err = "REPLAY";
        return false;
    }
    if (worker_announcement && claims_voter) {
        err = "VOTER_ANNOUNCEMENT";
        return false;
    }
    seen_nonces.insert(nonce);
    err.clear();
    return true;
}

bool SwarmCommitteeUnchanged(const std::vector<std::string>& current, const std::vector<std::string>& proposed)
{
    std::vector<std::string> left = current;
    std::vector<std::string> right = proposed;
    std::sort(left.begin(), left.end());
    std::sort(right.begin(), right.end());
    return left == right;
}

SwarmPublication SwarmPublishGraduation(bool quality_passed)
{
    SwarmPublication publication;
    publication.quality_graduated = quality_passed;
    publication.realm_promoted = false;
    publication.exact_replay_admitted = false;
    return publication;
}

} // namespace modelnet
