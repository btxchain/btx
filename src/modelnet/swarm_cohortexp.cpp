// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortexp.h>

#include <cstdint>

namespace modelnet {
namespace {

SwarmCohortExpiryResult Cohort(std::string& err)
{
    SwarmCohortExpiryResult result;
    result.admitted = false;
    result.expired = false;
    result.code = "COHORT";
    err = "COHORT";
    return result;
}

SwarmCohortExpiryResult Expired(std::string& err)
{
    SwarmCohortExpiryResult result;
    result.admitted = false;
    result.expired = true;
    result.code = "EXPIRED";
    err = "EXPIRED";
    return result;
}

SwarmCohortExpiryResult Quiet(const std::string& code, std::string& err)
{
    SwarmCohortExpiryResult result;
    result.admitted = false;
    result.expired = false;
    result.code = code;
    err.clear();
    return result;
}

} // namespace

SwarmCohortExpiryResult SwarmNoteCohortExpiry(const SwarmCohortExpiry& note, std::string& err)
{
    if (note.cohort_id.empty() || note.now_ms < 0 || note.until_ms < 1) {
        return Cohort(err);
    }
    // Equality is expiry, and it wins even when want_admit is true.
    // This note does not admit a member and does not start training.
    if (note.now_ms >= note.until_ms) {
        return Expired(err);
    }
    if (note.want_admit) {
        return Quiet("HELD", err);
    }
    return Quiet("NOTED", err);
}

} // namespace modelnet
