// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnologinpath2.h>

#include <string>

namespace modelnet {

SwarmNotNoLoginPath2Result SwarmNoteNotNoLoginPath2(const SwarmNotNoLoginPath2& note, std::string& err)
{
    SwarmNotNoLoginPath2Result result;
    // A unit note opens no Windows login path.
    result.logged_in = false;
    if (note.check_id.empty()) {
        result.code = "CHECK";
        result.logged_in = false;
        err = "CHECK";
        return result;
    }
    // A unit note opens no Windows login path.
    if (note.want_login) {
        result.code = "HELD";
        result.logged_in = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.logged_in = false;
    err.clear();
    return result;
}

} // namespace modelnet
