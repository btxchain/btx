// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_integerkeep.h>

namespace modelnet {

SwarmIntegerKeepResult SwarmKeepIntegerPairs(const SwarmIntegerKeep& pair, std::string& err)
{
    // INTEGER_LINEAR stays eight frozen pairs.
    SwarmIntegerKeepResult result;
    result.added = false;
    result.pairs = 8;
    if (pair.pair_id.empty()) {
        result.code = "PAIR";
        result.added = false;
        result.pairs = 8;
        err = "PAIR";
        return result;
    }
    if (pair.pairs != 8) {
        result.code = "RANGE";
        result.added = false;
        result.pairs = 8;
        err = "RANGE";
        return result;
    }
    if (pair.want_add) {
        result.code = "HELD";
        result.added = false;
        result.pairs = 8;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    result.pairs = 8;
    err.clear();
    return result;
}

} // namespace modelnet
