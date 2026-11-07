// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsigsize.h>

#include <string>

namespace modelnet {

SwarmNotSigSizeResult SwarmNoteNotSigSize(const SwarmNotSigSize& note, std::string& err)
{
    SwarmNotSigSizeResult result;
    result.verified = false;
    result.broadcast = false;
    if (note.witness_id.empty()) {
        result.code = "WITNESS";
        result.verified = false;
        result.broadcast = false;
        err = "WITNESS";
        return result;
    }
    // A signature-size check is not a verified funding witness.
    if (note.sig_bytes != 0) {
        result.code = "SIZE_ONLY";
        result.verified = false;
        result.broadcast = false;
        err = "SIZE_ONLY";
        return result;
    }
    if (note.want_verify) {
        result.code = "SIZE_ONLY";
        result.verified = false;
        result.broadcast = false;
        err = "SIZE_ONLY";
        return result;
    }
    result.code = "NOTED";
    result.verified = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
