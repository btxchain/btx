// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_COSTMETER_H
#define BTX_MODELNET_SWARM_COSTMETER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Caller-supplied cost measurements. A cost record keeps measured
 * integers and charges nothing.
 */
struct SwarmCostMeter {
    std::string cost_id;
    bool electricity_measured{false};
    bool wear_measured{false};
    bool network_measured{false};
    int64_t electricity{0};
    int64_t wear{0};
    int64_t network{0};
    bool want_charge{false};
};

/**
 * Outcome of recording a cost. charged stays false and atoms stays 0
 * on every path. A cost record keeps measured integers and charges
 * nothing.
 */
struct SwarmCostMeterResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
    int64_t electricity{0};
    int64_t wear{0};
    int64_t network{0};
};

/**
 * Record caller-supplied measurements without charging them.
 * Order, first match wins: an empty cost_id is COST and the three
 * stored amounts are 0. Any measured flag false is UNMEASURED and the
 * three stored amounts are 0, even when want_charge is false. Any
 * amount < 0 is RANGE and the three stored amounts are 0. want_charge
 * is HELD and the three amounts are copied. Otherwise the record is
 * NOTED, err is cleared, and the three amounts are copied. charged
 * stays false and atoms stays 0 on every path. A cost record keeps
 * measured integers and charges nothing.
 */
SwarmCostMeterResult SwarmRecordCostMeter(const SwarmCostMeter& meter, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_COSTMETER_H
