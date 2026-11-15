// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodownlic2.h>

#include <string>

namespace modelnet {

SwarmNotNoDownLic2Result SwarmNoteNotNoDownLic2(const SwarmNotNoDownLic2& note, std::string& err)
{
    SwarmNotNoDownLic2Result result;
    result.trained = false;
    result.redistributed = false;
    // A download license is not a training grant and not a redistribution grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.trained = false;
        result.redistributed = false;
        err = "LICENSE";
        return result;
    }
    if (note.download) {
        result.code = "NOT_GRANT";
        result.trained = false;
        result.redistributed = false;
        err = "NOT_GRANT";
        return result;
    }
    if (note.want_train || note.want_redistribute) {
        result.code = "NOT_GRANT";
        result.trained = false;
        result.redistributed = false;
        err = "NOT_GRANT";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.redistributed = false;
    err.clear();
    return result;
}

} // namespace modelnet
