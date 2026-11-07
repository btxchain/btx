// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scanabort.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmScanAbortResult SwarmAbortWrongType(const SwarmScanAbort& field, std::string& err)
{
    SwarmScanAbortResult result;
    result.continued = false;
    result.bytes_moved = 0;
    // A wrong-type field aborts the scan.
    if (field.field_id.empty()) {
        result.code = "FIELD";
        result.continued = false;
        result.bytes_moved = 0;
        err = "FIELD";
        return result;
    }
    if (field.wrong_type) {
        result.code = "ABORT";
        result.continued = false;
        result.bytes_moved = 0;
        err = "ABORT";
        return result;
    }
    if (field.want_continue) {
        result.code = "HELD";
        result.continued = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.continued = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
