// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/train_gate.h>

#include <modelnet/swarm_cpueval.h>

#include <vector>

namespace modelnet {

bool SwarmEvolveTrain::Train(std::string& err)
{
    if (m_stepped) {
        err = "REPLAY";
        return false;
    }

    SwarmCpuEval eval;
    eval.node_id = "integer-trainer";
    eval.cpu_available = true;
    eval.want_publish_rate = false;
    eval.want_gpu_claim = false;
    std::string note_err;
    const SwarmCpuEvalResult noted = SwarmNoteCpuEval(eval, note_err);
    if (noted.gpu_claimed || noted.published) {
        err = "GPU";
        return false;
    }

    const std::vector<IntegerExample>& data = IntegerDataset();
    if (data.size() != 8) {
        err = "PAIRS";
        return false;
    }

    IntegerTrainer trainer;
    if (!trainer.Step(err)) return false;
    const IntegerState state = trainer.State();
    if (state.step != 1 || state.state_hash.empty()) {
        err = "STEP";
        return false;
    }
    if (!trainer.ReplayMatches(state, err)) return false;

    m_state = state;
    m_step = state.step;
    m_state_hash = state.state_hash;
    m_gpu_ran = noted.gpu_claimed;
    m_trained = true;
    m_stepped = true;
    err.clear();
    return true;
}

void SwarmEvolveTrain::Reset()
{
    m_trained = false;
    m_stepped = false;
    m_gpu_ran = false;
    m_step = 0;
    m_state_hash.clear();
    m_state = IntegerState{};
}

} // namespace modelnet
