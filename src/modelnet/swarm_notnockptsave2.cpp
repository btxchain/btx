// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnockptsave2.h>

namespace modelnet {

SwarmNotNoCkptSave2Result SwarmNoteNotNoCkptSave2(const SwarmNotNoCkptSave2& note, std::string& err)
{
    SwarmNotNoCkptSave2Result result;
    result.saved = false;
    result.bytes_moved = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        err = "RUN";
        return result;
    }
    if (note.want_save) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
