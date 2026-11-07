// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosigner.h>

#include <string>

namespace modelnet {

SwarmNotNoSignerResult SwarmNoteNotNoSigner(const SwarmNotNoSigner& note, std::string& err)
{
    SwarmNotNoSignerResult result;
    result.started = false;
    result.signed_block = false;
    // This note does not start a signer or sign a block.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.started = false;
        result.signed_block = false;
        err = "NODE";
        return result;
    }
    if (note.want_start) {
        result.code = "HELD";
        result.started = false;
        result.signed_block = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.started = false;
    result.signed_block = false;
    err.clear();
    return result;
}

} // namespace modelnet
