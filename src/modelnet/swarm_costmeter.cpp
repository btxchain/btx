// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_costmeter.h>

namespace modelnet {

SwarmCostMeterResult SwarmRecordCostMeter(const SwarmCostMeter& meter, std::string& err)
{
    // A cost record keeps measured integers and charges nothing.
    SwarmCostMeterResult result;
    result.charged = false;
    result.atoms = 0;
    result.electricity = 0;
    result.wear = 0;
    result.network = 0;
    if (meter.cost_id.empty()) {
        result.code = "COST";
        result.charged = false;
        result.atoms = 0;
        result.electricity = 0;
        result.wear = 0;
        result.network = 0;
        err = "COST";
        return result;
    }
    if (!meter.electricity_measured || !meter.wear_measured || !meter.network_measured) {
        result.code = "UNMEASURED";
        result.charged = false;
        result.atoms = 0;
        result.electricity = 0;
        result.wear = 0;
        result.network = 0;
        err = "UNMEASURED";
        return result;
    }
    if (meter.electricity < 0 || meter.wear < 0 || meter.network < 0) {
        result.code = "RANGE";
        result.charged = false;
        result.atoms = 0;
        result.electricity = 0;
        result.wear = 0;
        result.network = 0;
        err = "RANGE";
        return result;
    }
    if (meter.want_charge) {
        result.code = "HELD";
        result.charged = false;
        result.atoms = 0;
        result.electricity = meter.electricity;
        result.wear = meter.wear;
        result.network = meter.network;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    result.electricity = meter.electricity;
    result.wear = meter.wear;
    result.network = meter.network;
    err.clear();
    return result;
}

} // namespace modelnet
