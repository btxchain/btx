// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bound/swarm_bound.h>

#include <vector>

namespace modelnet {
namespace {

constexpr char kPrompt[] = "abcdefgh";

bool PullMemory(SwarmDecodeRun& decode, std::string& err)
{
    if (!decode.Open("mem", "memory", err)) return false;
    if (!decode.Open("vendor", "vllm", err)) return false;
    if (!decode.Prompt("mem", kPrompt, false, err)) return false;
    if (!decode.Prompt("vendor", kPrompt, false, err)) return false;
    for (int i = 0; i < 8; ++i) {
        if (!decode.Pull("mem", err)) return false;
    }
    if (decode.Pull("mem", err)) {
        err = "DONE";
        return false;
    }
    if (err != "DONE") return false;
    if (decode.tokens() != static_cast<int64_t>(8)) {
        err = "TOKENS";
        return false;
    }
    if (decode.Pull("vendor", err)) {
        err = "VENDOR";
        return false;
    }
    if (err != NIFDT_ENGINE_ABSENT) return false;
    err.clear();
    return true;
}

bool TrainOnce(DtDense& dense, std::string& err)
{
    std::vector<float> input(static_cast<std::size_t>(DtDense::kSequence * DtDense::kHidden), 0.25f);
    if (!dense.Forward(input, err)) return false;
    if (!dense.Backward(err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD0, dense.ConsumerGradient(DT_DENSE_HEAD0), err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD1, dense.ConsumerGradient(DT_DENSE_HEAD1), err)) return false;
    if (!dense.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.01f, err)) return false;
    if (dense.adam_step() != static_cast<int64_t>(1)) {
        err = "STEP";
        return false;
    }
    if (dense.GpuStep(err)) {
        err = "GPU";
        return false;
    }
    if (err != NIFDT_ENGINE_ABSENT) return false;
    err.clear();
    return !dense.gpu() && !dense.qualified_v41();
}

} // namespace

bool SwarmBoundProbe::Once(std::string& err)
{
    if (!PullMemory(m_decode, err)) return false;
    m_remote = NIFDT_ENGINE_ABSENT;
    if (!TrainOnce(m_dense, err)) return false;
    const std::vector<unsigned char> a{1, 2, 3, 4};
    const std::vector<unsigned char> b{5, 6, 7, 8};
    if (!m_pair.Exchange(a, b, err)) return false;
    if (m_pair.physical_hosts() != 1 || m_pair.bytes_moved() <= 0 || m_pair.gpu()) {
        err = "HOSTS";
        return false;
    }
    if (!m_replay.Run(1, err)) return false;
    if (!m_replay.Check(err)) return false;
    m_replay_ok = true;
    if (m_replay.pairs() != static_cast<int64_t>(8)) {
        err = "PAIRS";
        return false;
    }
    if (!m_snap.Publish(1, "d1", "body", err)) return false;
    if (!m_snap.Pull(1, "d1", err)) return false;
    if (m_snap.Hosts(2, err)) {
        err = "HOSTS";
        return false;
    }
    if (err != SNAPSHOT_PULL_HOSTS) return false;
    if (!m_roles.Seat("ingress", err)) return false;
    if (!m_roles.Advance(0, err)) return false;
    if (m_roles.Hosts(2, err)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return m_roles.hosts() == static_cast<int64_t>(1) && !m_decode.launched() && !m_decode.gpu();
}

bool SwarmBoundProbe::Pass(int64_t now_ms, std::string& err)
{
    if (m_ticks < INT64_MAX) ++m_ticks;
    m_now_ms = now_ms;
    if (m_done) {
        err.clear();
        return true;
    }
    if (!Once(err)) return false;
    m_done = true;
    err.clear();
    return true;
}

bool SwarmBoundProbe::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool SwarmBoundProbe::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
