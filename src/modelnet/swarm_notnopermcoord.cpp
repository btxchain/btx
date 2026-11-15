// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopermcoord.h>

#include <string>

namespace modelnet {

SwarmNotNoPermCoordResult SwarmNoteNotNoPermCoord(const SwarmNotNoPermCoord& note, std::string& err)
{
    SwarmNotNoPermCoordResult result;
    result.replaced = false;
    result.trained = false;
    // Permanent coordinator loss does not install a replacement and does not train.
    // Earned rows stay.
    if (note.coord_id.empty()) {
        result.code = "COORD";
        result.replaced = false;
        result.trained = false;
        err = "COORD";
        return result;
    }
    // gone is PERMANENT even when want_replace is false.
    if (note.gone) {
        result.code = "PERMANENT";
        result.replaced = false;
        result.trained = false;
        err = "PERMANENT";
        return result;
    }
    if (note.want_replace) {
        result.code = "HELD";
        result.replaced = false;
        result.trained = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.replaced = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
