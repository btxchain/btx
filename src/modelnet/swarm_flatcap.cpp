// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flatcap.h>

namespace modelnet {

// The flat manifest cap stays 16384 bytes.
SwarmFlatCapResult SwarmKeepFlatCap(const SwarmFlatCap& manifest, std::string& err)
{
    SwarmFlatCapResult out;
    out.raised = false;
    out.bytes = 16384;
    if (manifest.manifest_id.empty()) {
        out.code = "MANIFEST";
        err = "MANIFEST";
        out.raised = false;
        out.bytes = 16384;
        return out;
    }
    if (manifest.want_raise) {
        out.code = "HELD";
        err = "HELD";
        out.raised = false;
        out.bytes = 16384;
        return out;
    }
    out.code = "NOTED";
    err.clear();
    out.raised = false;
    out.bytes = 16384;
    return out;
}

} // namespace modelnet
