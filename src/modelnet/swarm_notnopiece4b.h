// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPIECE4B_H
#define BTX_MODELNET_SWARM_NOTNOPIECE4B_H

#include <string>

namespace modelnet {

struct SwarmNotNoPiece4b {
    std::string piece_id;
    int bytes{0};
    bool want_split{false};
};

struct SwarmNotNoPiece4bResult {
    std::string code;
    bool split{false};
    bool bytes_moved{false};
};

// A piece split is 4 MiB. This note splits nothing.
SwarmNotNoPiece4bResult SwarmNoteNotNoPiece4b(const SwarmNotNoPiece4b& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPIECE4B_H
