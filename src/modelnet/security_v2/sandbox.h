// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_SANDBOX_H
#define BITCOIN_MODELNET_SECURITY_V2_SANDBOX_H
#include <modelnet/security_v2/common.h>
#include <functional>
namespace modelnet::security {
struct SandboxLimits {
    uint64_t memory_bytes{256ull*1024*1024};
    uint64_t wall_ms{5000};
    uint64_t cpu_ms{3000};
    uint64_t output_bytes{1024*1024};
};
struct SandboxResult {
    bool dispatched{false}, enforced{false}, cancelled{false}, timed_out{false};
    int exit_code{-1};
    std::string profile, output, error, executable_digest;
    uint64_t elapsed_ms{0};
};
/** Descriptor-only Linux worker. Executable must be a static ELF. The exact
 * verified bytes are sealed in a memfd; seccomp denies every filesystem open,
 * every socket, fork/clone, exec except the initial sealed fd, and authority
 * syscalls. Only bounded stdin/stdout/stderr are exposed. No namespace support
 * is assumed. This is not a general dynamic/GPU runtime sandbox. */
SandboxResult RunStaticWorker(const fs::path& executable, const std::string& expected_digest,
                              std::string_view input, const SandboxLimits& limits,
                              const std::function<bool()>& still_authorized);
std::string StaticSandboxDigest();
} // namespace modelnet::security
#endif
