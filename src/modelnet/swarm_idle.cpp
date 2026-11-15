// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idle.h>

#include <string>

namespace modelnet {

SwarmIdleDefaultResult SwarmNoteIdleDefault(const SwarmIdleDefault& idle, std::string& err)
{
    SwarmIdleDefaultResult result;
    result.trainer = false;
    result.seeder = false;
    result.evaluator = false;
    result.spend_armed = false;
    result.spend = "0";
    if (idle.node_id.empty()) {
        result.code = "IDLE";
        err = "IDLE";
        return result;
    }
    // This note does not interpret a present device file.
    if (idle.device_json_present) {
        result.trainer = false;
        result.seeder = false;
        result.evaluator = false;
        result.spend_armed = false;
        result.spend = "0";
        result.code = "PRESENT";
        err = "PRESENT";
        return result;
    }
    // want_train wins even when want_spend or want_private is true.
    // An absent device file is not a trainer. Nothing is signed.
    if (idle.want_train) {
        result.trainer = false;
        result.seeder = false;
        result.evaluator = false;
        result.spend_armed = false;
        result.spend = "0";
        result.code = "NOT_TRAINER";
        err = "NOT_TRAINER";
        return result;
    }
    if (idle.want_spend) {
        result.trainer = false;
        result.seeder = false;
        result.evaluator = false;
        result.spend_armed = false;
        result.spend = "0";
        result.code = "SPEND_REFUSED";
        err = "SPEND_REFUSED";
        return result;
    }
    if (idle.want_private) {
        result.trainer = false;
        result.seeder = false;
        result.evaluator = false;
        result.spend_armed = false;
        result.spend = "0";
        result.code = "PRIVATE_REFUSED";
        err = "PRIVATE_REFUSED";
        return result;
    }
    // An absent device file yields a seeder and an evaluator, not a
    // trainer, and spending stays off. Nothing is broadcast.
    result.trainer = false;
    result.seeder = true;
    result.evaluator = true;
    result.spend_armed = false;
    result.spend = "0";
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
