// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofetch.h>

#include <string>

namespace modelnet {

SwarmNotNoFetchResult SwarmNoteNotNoFetch(const SwarmNotNoFetch& note, std::string& err)
{
    // This note fetches no dependency and moves no bytes.
    SwarmNotNoFetchResult result;
    result.fetched = false;
    result.bytes_moved = false;
    if (note.dep_id.empty()) {
        result.code = "DEP";
        result.fetched = false;
        result.bytes_moved = false;
        err = "DEP";
        return result;
    }
    if (note.want_fetch) {
        result.code = "NOT_FETCHED";
        result.fetched = false;
        result.bytes_moved = false;
        err = "NOT_FETCHED";
        return result;
    }
    result.code = "NOTED";
    result.fetched = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
