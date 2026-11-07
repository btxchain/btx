// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_publishback.h>

namespace modelnet {

SwarmPublishBackResult SwarmNotePublishBack(const SwarmPublishBack& note, std::string& err)
{
    SwarmPublishBackResult result;
    result.published = false;
    result.authority = false;
    if (note.model_id.empty()) {
        result.code = "ORIGIN";
        err = "ORIGIN";
        return result;
    }
    // A Hugging Face publish-back is an origin, not lineage authority.
    // NOT_AUTHORITY wins even when hugging_face is true. This note does
    // not publish.
    if (note.want_publish_back) {
        result.code = "NOT_AUTHORITY";
        err = "NOT_AUTHORITY";
        return result;
    }
    if (note.hugging_face) {
        result.code = "HELD";
        result.published = false;
        result.authority = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.authority = false;
    err.clear();
    return result;
}

} // namespace modelnet
