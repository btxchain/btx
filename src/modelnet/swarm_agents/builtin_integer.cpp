// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/builtin.h>

#include <modelnet/swarm_agents/codes.h>
#include <modelnet/training_integer.h>

#include <string>

namespace modelnet {

bool SwarmAgentRunIntegerStep(SwarmAgentBuiltinResult& out, std::string& err)
{
    out = SwarmAgentBuiltinResult{};
    out.launched = false;
    if (IntegerDataset().size() != 8) {
        err = kAgentInteger;
        return false;
    }

    // One step on this trainer. The eight frozen pairs are not extended.
    // No device is selected and nothing here reports that a GPU ran.
    IntegerTrainer trainer;
    std::string step_err;
    if (!trainer.Step(step_err)) {
        out = SwarmAgentBuiltinResult{};
        err = kAgentInteger;
        return false;
    }
    if (trainer.State().step != 1 || trainer.State().state_hash.empty()) {
        out = SwarmAgentBuiltinResult{};
        err = kAgentInteger;
        return false;
    }

    std::string replay_err;
    if (!trainer.ReplayMatches(trainer.State(), replay_err)) {
        out = SwarmAgentBuiltinResult{};
        err = kAgentInteger;
        return false;
    }
    if (trainer.State().step != 1) {
        out = SwarmAgentBuiltinResult{};
        err = kAgentInteger;
        return false;
    }

    out.ran = true;
    out.launched = false;
    out.has_result = true;
    out.step = trainer.State().step;
    out.result_hash = trainer.State().state_hash;
    err.clear();
    return true;
}

} // namespace modelnet
