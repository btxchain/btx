// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopreimage.h>

#include <string>

namespace modelnet {

SwarmNotNoPreimageResult SwarmNoteNotNoPreimage(const SwarmNotNoPreimage& note, std::string& err)
{
    SwarmNotNoPreimageResult result;
    result.claimed = false;
    result.atoms = 0;
    // A preimage of the wrong length claims nothing.
    if (note.preimage_id.empty()) {
        result.code = "PREIMAGE";
        result.claimed = false;
        result.atoms = 0;
        err = "PREIMAGE";
        return result;
    }
    if (note.length != 32) {
        result.code = "REFUSED";
        result.claimed = false;
        result.atoms = 0;
        err = "REFUSED";
        return result;
    }
    if (note.want_claim) {
        result.code = "REFUSED";
        result.claimed = false;
        result.atoms = 0;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.claimed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
