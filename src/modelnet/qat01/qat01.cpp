// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qat01/qat01.h>
#include <modelnet/nifdt_contract/contract.h>

#include <modelnet/dt_dense/dt_dense.h>
#include <modelnet/nif_lifecycle/nif_lifecycle.h>
#include <modelnet/swarm_lifecycle.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool CallPublicLifecycle(std::string& err)
{
    NifLifecycle life;
    if (!life.available() || life.validation_affected() || life.authority_from_receipt()) {
        err = "LIFECYCLE";
        return false;
    }
    if (life.launched() || life.gpu() || life.broadcast()) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (life.bytes_moved() != static_cast<int64_t>(0) || life.automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (life.Find("DT-Q01") != nullptr) {
        err = "LIFECYCLE";
        return false;
    }

    SwarmDevice device;
    device.idle_contribution = true;
    device.slots = 1;
    const SwarmBudget budget = SwarmGovern(device, 1);
    if (budget.code != "ADMITTED" || budget.active_workers != 1 || budget.drained) {
        err = "LIFECYCLE";
        return false;
    }
    err.clear();
    return true;
}

bool CallDenseCpu(std::string& err)
{
    DtDense dense;
    const std::vector<float> input(static_cast<std::size_t>(DtDense::kSequence * DtDense::kHidden), 0.25f);
    if (!dense.Forward(input, err)) return false;
    if (!dense.Backward(err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD0, dense.ConsumerGradient(DT_DENSE_HEAD0), err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD1, dense.ConsumerGradient(DT_DENSE_HEAD1), err)) return false;
    if (!dense.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.01f, err)) return false;
    if (dense.adam_step() != static_cast<std::int64_t>(1)) {
        err = "STEP";
        return false;
    }
    if (dense.GpuStep(err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (dense.gpu() || dense.qualified_v41() || dense.launched() || dense.broadcast()) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (dense.bytes_moved() != static_cast<std::int64_t>(0) || dense.atoms_moved() != static_cast<std::int64_t>(0)) {
        err = "BYTES";
        return false;
    }
    err.clear();
    return true;
}

} // namespace

bool Qat01::covered(const std::string& id) const
{
    if (!m_done) return false;
    return id == "DT-Q01" || id == "DT-Q02" || id == "DT-Q03";
}

bool Qat01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (m_lifecycle_calls != static_cast<int64_t>(0) || m_dense_steps != static_cast<int64_t>(0)) {
        err = "STEP";
        return false;
    }
    if (!CallPublicLifecycle(err)) return false;
    if (!CallDenseCpu(err)) return false;
    if (Gpu(err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (Hosts(static_cast<int64_t>(2), err) || err != "HOSTS") return false;
    if (passed() || gpu_passed() || release_qualified() || hardware_qualified() || qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (launched() || gpu() || broadcast() || process_present()) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (bytes_moved() != static_cast<int64_t>(0) || automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (scenario_status() != "NOT_RUN") {
        err = "NOT_RUN";
        return false;
    }
    if (covered("DT-Q01") || covered("DT-Q04")) {
        err = "ID";
        return false;
    }
    m_lifecycle_calls = static_cast<int64_t>(1);
    m_dense_steps = static_cast<int64_t>(1);
    m_done = true;
    if (!covered("DT-Q01") || !covered("DT-Q02") || !covered("DT-Q03") || covered("DT-Q04")) {
        m_done = false;
        m_lifecycle_calls = static_cast<int64_t>(0);
        m_dense_steps = static_cast<int64_t>(0);
        err = "ID";
        return false;
    }
    err.clear();
    return true;
}

bool Qat01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Qat01::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Qat01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Qat01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
