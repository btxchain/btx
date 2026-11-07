// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notenv.h>

namespace modelnet {

SwarmNotEnvResult SwarmNoteNotEnv(const SwarmNotEnv& note, std::string& err)
{
    SwarmNotEnvResult result;
    result.enabled = false;
    result.required_env = false;
    if (note.feature_id.empty()) {
        result.code = "FEATURE";
        result.enabled = false;
        result.required_env = false;
        err = "FEATURE";
        return result;
    }
    // Normal use must not require a manual environment variable or feature switch.
    if (note.env_required || note.want_enable) {
        result.code = "NO_SWITCH";
        result.enabled = false;
        result.required_env = false;
        err = "NO_SWITCH";
        return result;
    }
    result.code = "NOTED";
    result.enabled = false;
    result.required_env = false;
    err.clear();
    return result;
}

} // namespace modelnet
