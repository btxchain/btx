// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SCANABORT_H
#define BTX_MODELNET_SWARM_SCANABORT_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmScanAbort {
    std::string field_id;
    bool wrong_type{false};
    bool want_continue{false};
};

struct SwarmScanAbortResult {
    std::string code;
    bool continued{false};
    int64_t bytes_moved{0};
};

// A wrong-type field aborts the scan.
SwarmScanAbortResult SwarmAbortWrongType(const SwarmScanAbort& field, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SCANABORT_H
