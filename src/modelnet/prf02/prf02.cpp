// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf02/prf02.h>
#include <modelnet/dt_dense/dt_dense.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool CpuDenseStep(std::string& err)
{
    DtDense dense;
    const std::vector<float> input(static_cast<std::size_t>(DtDense::kSequence * DtDense::kHidden), 0.25f);
    if (!dense.Forward(input, err)) return false;
    if (!dense.Backward(err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD0, dense.ConsumerGradient(DT_DENSE_HEAD0), err)) return false;
    if (!dense.NoteContribution(DT_DENSE_HEAD1, dense.ConsumerGradient(DT_DENSE_HEAD1), err)) return false;
    if (!dense.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.01f, err)) return false;
    if (dense.adam_step() != static_cast<int64_t>(1)) {
        err = "STEP";
        return false;
    }
    if (dense.qualified_v41() || dense.gpu()) {
        err = "QUALIFIED";
        return false;
    }
    err.clear();
    return true;
}

} // namespace

bool Prf02::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (!CpuDenseStep(err)) return false;
    m_done = true;
    err.clear();
    return true;
}

bool Prf02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Prf02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf02::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
