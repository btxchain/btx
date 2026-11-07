// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivate2.h>

#include <string>

namespace modelnet {

SwarmNotNoPrivate2Result SwarmNoteNotNoPrivate2(const SwarmNotNoPrivate2& note, std::string& err)
{
    SwarmNotNoPrivate2Result result;
    result.published = false;
    // A private family is not published.
    if (note.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        err = "FAMILY";
        return result;
    }
    if (note.private_family) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        err = "NOT_PUBLISHED";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
