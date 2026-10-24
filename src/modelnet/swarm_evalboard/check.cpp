// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalboard/check.h>

#include <modelnet/swarm_evalboard/codes.h>
#include <modelnet/swarm_evalboard/limits.h>

namespace modelnet {

bool SwarmEvalAdmitReport(const std::string& subject, const std::string& author, const std::string& domain,
                          int64_t score, bool independent, bool rotating, std::string& err)
{
    if (subject.empty() || author.empty() || domain.empty()) {
        err = kSwarmEvalReport;
        return false;
    }
    // An author does not score their own subject.
    if (author == subject) {
        err = kSwarmEvalNotScored;
        return false;
    }
    if (!independent) {
        err = kSwarmEvalHeld;
        return false;
    }
    if (!rotating) {
        err = kSwarmEvalNotRotating;
        return false;
    }
    if (score < kSwarmEvalScoreMin || score > kSwarmEvalScoreMax) {
        err = kSwarmEvalRange;
        return false;
    }
    return true;
}

} // namespace modelnet
