// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notelectric.h>

namespace modelnet {

SwarmNotElectricResult SwarmNoteNotElectric(const SwarmNotElectric& note, std::string& err)
{
    // Publication never happens. watt_hours stays 0. This note does not read a meter.
    SwarmNotElectricResult out;
    out.published = false;
    out.watt_hours = 0;

    if (note.meter_id.empty()) {
        out.code = "METER";
        err = "METER";
        return out;
    }
    if (note.want_publish) {
        out.code = "UNMEASURED";
        err = "UNMEASURED";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
