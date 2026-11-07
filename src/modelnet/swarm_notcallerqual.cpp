// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcallerqual.h>

namespace modelnet {

SwarmNotCallerQualResult SwarmNoteNotCallerQual(const SwarmNotCallerQual& note, std::string& err)
{
    SwarmNotCallerQualResult result;
    result.qualified = false;
    result.advertised = false;
    // A caller-supplied token rate does not start a runtime and does not
    // qualify an engine. tokens_per_sec is not copied into the result.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.qualified = false;
        result.advertised = false;
        err = "ENGINE";
        return result;
    }
    if (note.want_qualify) {
        result.code = "UNMEASURED";
        result.qualified = false;
        result.advertised = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    result.advertised = false;
    err.clear();
    return result;
}

} // namespace modelnet
