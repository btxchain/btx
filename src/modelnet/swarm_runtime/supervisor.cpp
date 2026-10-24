// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license. See COPYING.
#include "supervisor.h"
#include <array>
#include <cstdio>
#include <set>
#include <stdexcept>
#ifndef _WIN32
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

namespace modelnet::swarm {
std::filesystem::path ExecutableDirectory()
{
    std::array<char, 4096> path{};
#ifdef __linux__
    auto n = readlink("/proc/self/exe", path.data(), path.size() - 1);
    if (n > 0) return std::filesystem::path(std::string(path.data(), n)).parent_path();
#elif defined(__APPLE__)
    uint32_t size = path.size();
    if (_NSGetExecutablePath(path.data(), &size) == 0)
        return std::filesystem::weakly_canonical(path.data()).parent_path();
#endif
    return {};
}

std::vector<std::string> SanitizeEnvironment(char* const envp[])
{
    // An allowlist is deliberately narrower than searching for "wallet".
    static const std::set<std::string> allowed{
        "HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "USER", "LOGNAME",
        "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES"
    };
    std::vector<std::string> result;
    if (envp) for (auto p = envp; *p; ++p) {
        const std::string entry(*p);
        const auto equal = entry.find('=');
        if (equal != std::string::npos && allowed.count(entry.substr(0, equal)))
            result.push_back(entry);
    }
    result.emplace_back("PYTHONNOUSERSITE=1");
    result.emplace_back("HF_HUB_OFFLINE=1");
    result.emplace_back("TRANSFORMERS_OFFLINE=1");
    result.emplace_back("DO_NOT_TRACK=1");
    return result;
}

Supervisor::Supervisor(std::filesystem::path modeldir, std::filesystem::path executable)
    : m_modeldir(std::move(modeldir)), m_executable(std::move(executable))
{
    // Stored only. An empty path stays empty. The worker thread does not
    // launch a sidecar, and btxd does not default that path to a second binary.
    m_thread = std::thread([this] { Run(); });
}
Supervisor::~Supervisor() { Stop(); }
void Supervisor::Stop() noexcept
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stop.store(true);
    }
    m_wake.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

void Supervisor::Run() noexcept
{
    try {
        const auto data = m_modeldir / "swarm";
        if (std::filesystem::is_symlink(data)) throw std::runtime_error("swarm data symlink");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "BTX swarm sidecar stopped: %s; monetary operation is unchanged\n", e.what());
        return;
    } catch (...) {
        std::fprintf(stderr, "BTX swarm sidecar stopped; monetary operation is unchanged\n");
        return;
    }
    std::fprintf(stderr, "BTX swarm control plane is inside btxd; a sidecar is not launched\n");
    std::unique_lock<std::mutex> lock(m_mutex);
    m_wake.wait(lock, [this] { return m_stop.load(); });
}
}
