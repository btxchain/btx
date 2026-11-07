// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdbook.h>

namespace modelnet {

// A fixed holdout can be indexed and cannot rotate or publish a score.
SwarmHoldBookResult SwarmUseHoldout(const SwarmHoldBook& book, std::string& err)
{
    SwarmHoldBookResult result;
    result.rotated = false;
    result.scored = false;

    if (book.holdout_id.empty()) {
        result.code = "HOLDOUT";
        err = "HOLDOUT";
        result.rotated = false;
        result.scored = false;
        result.index = 0;
        result.members = 0;
        return result;
    }
    if (book.members <= 0) {
        result.code = "EMPTY";
        err = "EMPTY";
        result.rotated = false;
        result.scored = false;
        result.index = 0;
        result.members = 0;
        return result;
    }
    if (book.index < 0 || book.index >= book.members) {
        result.code = "INDEX";
        err = "INDEX";
        result.rotated = false;
        result.scored = false;
        result.index = 0;
        result.members = book.members;
        return result;
    }
    if (book.want_rotate) {
        result.code = "NOT_ROTATING";
        err = "NOT_ROTATING";
        result.rotated = false;
        result.scored = false;
        result.index = book.index;
        result.members = book.members;
        return result;
    }
    if (book.want_score) {
        result.code = "HELD";
        err = "HELD";
        result.rotated = false;
        result.scored = false;
        result.index = book.index;
        result.members = book.members;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.rotated = false;
    result.scored = false;
    result.index = book.index;
    result.members = book.members;
    return result;
}

} // namespace modelnet
