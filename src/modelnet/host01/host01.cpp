// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/host01/host01.h>

#include <string>

namespace modelnet {

bool Host01::Bind(const std::string& role, const std::string& endpoint, std::string& err)
{
    if (role != "cpu" && role != "gpu") {
        err = "ROLE";
        return false;
    }
    if (endpoint.empty()) {
        err = "FIELD";
        return false;
    }
    if (endpoint.find("://") != std::string::npos) {
        err = "FIELD";
        return false;
    }
    if (endpoint == "localhost" || endpoint == "127.0.0.1") {
        err = "LOOPBACK";
        return false;
    }
    if (role == "cpu") {
        if (m_cpu) {
            err = NIFDT_REPLAY;
            return false;
        }
        m_cpu_endpoint = endpoint;
        m_cpu = true;
    } else {
        if (m_gpu) {
            err = NIFDT_REPLAY;
            return false;
        }
        m_gpu_endpoint = endpoint;
        m_gpu = true;
    }
    err.clear();
    return true;
}

bool Host01::bound(const std::string& role) const
{
    if (role == "cpu") return m_cpu;
    if (role == "gpu") return m_gpu;
    return false;
}

std::string Host01::endpoint(const std::string& role) const
{
    if (role == "cpu" && m_cpu) return m_cpu_endpoint;
    if (role == "gpu" && m_gpu) return m_gpu_endpoint;
    return std::string();
}

int64_t Host01::physical_hosts() const
{
    if (m_cpu && m_gpu) return static_cast<int64_t>(2);
    return static_cast<int64_t>(1);
}

bool Host01::Ready(std::string& err) const
{
    if (m_cpu && m_gpu) {
        err.clear();
        return true;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
