// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag09.h>

namespace modelnet {

SwarmFlag09Result SwarmStageGraduate(const SwarmFlag09& in, std::string& err)
{
    SwarmFlag09Result result;
    result.issued = false;
    result.realm = false;
    result.replay_admitted = false;
    result.passed = false;
    if (in.descendant_id.empty()) {
        result.code = "DESCENDANT";
        result.issued = false;
        result.realm = false;
        result.replay_admitted = false;
        result.passed = false;
        err = "DESCENDANT";
        return result;
    }
    // A certificate requires a qualified real descendant. This wins even when want_cert is true.
    if (!in.qualified || !in.real_run) {
        result.code = "NO_CERT";
        result.issued = false;
        result.realm = false;
        result.replay_admitted = false;
        result.passed = false;
        err = "NO_CERT";
        return result;
    }
    // Quality is not realm promotion and not ExactReplay admission.
    if (in.want_realm) {
        result.code = "NOT_REALM";
        result.issued = false;
        result.realm = false;
        result.replay_admitted = false;
        result.passed = false;
        err = "NOT_REALM";
        return result;
    }
    if (in.want_cert) {
        result.code = "HELD";
        result.issued = false;
        result.realm = false;
        result.replay_admitted = false;
        result.passed = false;
        err.clear();
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.issued = false;
        result.realm = false;
        result.replay_admitted = false;
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.issued = false;
    result.realm = false;
    result.replay_admitted = false;
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
