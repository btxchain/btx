// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPIECE4MIB2_H
#define BTX_MODELNET_SWARM_NOTNOPIECE4MIB2_H

#include <string>
#include <cstdint>

namespace modelnet {

struct SwarmNotNoPiece4Mib2 {
    std::string piece_id;
    uint64_t size_bytes{0};
    bool want_split{false};
};

struct SwarmNotNoPiece4Mib2Result {
    std::string code;
    bool split{false};
};

// A piece split stays 4 MiB and this note splits nothing.
SwarmNotNoPiece4Mib2Result SwarmNoteNotNoPiece4Mib2(const SwarmNotNoPiece4Mib2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPIECE4MIB2_H
