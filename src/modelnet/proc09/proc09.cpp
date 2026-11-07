// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc09/proc09.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>
#include <vector>

namespace modelnet {

bool Proc09::Deliver(const std::string& fingerprint, const std::string& log_digest, const std::vector<std::string>& blockers, std::string& err)
{
    if (fingerprint.empty()) {
        err = "FIELD";
        return false;
    }
    if (log_digest.empty()) {
        err = "FIELD";
        return false;
    }
    if (blockers.empty()) {
        err = "FIELD";
        return false;
    }
    for (const std::string& blocker : blockers) {
        if (blocker.empty()) {
            err = "FIELD";
            return false;
        }
    }
    if (m_done) {
        err = "REPLAY";
        return false;
    }
    m_fingerprint = fingerprint;
    m_log_digest = log_digest;
    m_blockers = blockers;
    m_done = true;
    err.clear();
    return true;
}

bool Proc09::ClaimTaskCount(int count, std::string& err)
{
    static_cast<void>(count);
    err = "CLAIM";
    return false;
}

} // namespace modelnet
