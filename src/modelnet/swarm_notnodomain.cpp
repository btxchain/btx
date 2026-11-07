// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodomain.h>

#include <string>

namespace modelnet {

SwarmNotNoDomainResult SwarmNoteNotNoDomain(const SwarmNotNoDomain& note, std::string& err)
{
    SwarmNotNoDomainResult result;
    result.settled = false;
    result.bytes_moved = false;
    // The same trust domain does not settle a report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.settled = false;
        result.bytes_moved = false;
        err = "REPORT";
        return result;
    }
    if (note.same_domain) {
        result.code = "SAME_DOMAIN";
        result.settled = false;
        result.bytes_moved = false;
        err = "SAME_DOMAIN";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
