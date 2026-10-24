// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohf.h>

#include <string>

namespace modelnet {

SwarmNotNoHfResult SwarmNoteNotNoHf(const SwarmNotNoHf& note, std::string& err)
{
    SwarmNotNoHfResult result;
    result.authority = false;
    result.published = false;
    // A Hugging Face import is not lineage authority.
    if (note.origin_id.empty()) {
        result.code = "ORIGIN";
        result.authority = false;
        result.published = false;
        err = "ORIGIN";
        return result;
    }
    if (note.want_authority) {
        result.code = "NOT_AUTHORITY";
        result.authority = false;
        result.published = false;
        err = "NOT_AUTHORITY";
        return result;
    }
    result.code = "NOTED";
    result.authority = false;
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
