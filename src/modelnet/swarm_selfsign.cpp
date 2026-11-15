// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_selfsign.h>

namespace modelnet {

SwarmSelfSignResult SwarmNoteSelfSign(const SwarmSelfSign& report, std::string& err)
{
    SwarmSelfSignResult result;
    result.signed_ok = false;
    if (report.report_id.empty()) {
        result.signed_ok = false;
        result.code = "REPORT";
        err = "REPORT";
        return result;
    }
    // An author does not sign their own report.
    // NOT_SIGNED wins even when want_sign is false.
    if (report.same_author) {
        result.signed_ok = false;
        result.code = "NOT_SIGNED";
        err = "NOT_SIGNED";
        return result;
    }
    if (report.want_sign) {
        result.signed_ok = false;
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.signed_ok = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
