// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qat02/qat02.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Refuse(const std::string& name, std::string& err)
{
    if (!NifDtEngineLinked(name)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    err = NIFDT_NO_ROUTE;
    return false;
}

} // namespace

bool Qat02::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (FabricDispatch("rdma", err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (FabricDispatch("nvlink", err) || err != NIFDT_NO_ROUTE) return false;
    if (PipelineOverlap("dualpipe", err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (PipelineOverlap("stage", err) || err != NIFDT_NO_ROUTE) return false;
    if (ShardedOptimizer("deepgemm", err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (ShardedOptimizer("shard", err) || err != NIFDT_NO_ROUTE) return false;
    if (bytes_moved() != static_cast<int64_t>(0) || socket_opened() || device_present()) {
        err = NIFDT_NO_ROUTE;
        return false;
    }
    if (passed() || gpu_passed() || release_qualified() || hardware_qualified() || qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Qat02::FabricDispatch(const std::string& name, std::string& err)
{
    return Refuse(name, err);
}

bool Qat02::PipelineOverlap(const std::string& name, std::string& err)
{
    return Refuse(name, err);
}

bool Qat02::ShardedOptimizer(const std::string& name, std::string& err)
{
    return Refuse(name, err);
}

bool Qat02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Qat02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Qat02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Qat02::covered(const std::string& id) const
{
    if (!m_done) return false;
    return id == "DT-Q04" || id == "DT-Q05" || id == "DT-Q06";
}

} // namespace modelnet
