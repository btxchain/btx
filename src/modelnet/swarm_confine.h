// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CONFINE_H
#define BTX_MODELNET_SWARM_CONFINE_H

#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Execute an owner-selected helper with bounded CPU/address space/descriptors
 * and no network. Linux uses user/network namespaces and no_new_privs;
 * macOS uses a parameterized default-deny Seatbelt profile, and the child
 * execs only after it proves the profile (a directory outside root stops
 * opening, a loopback bind is refused). The profile also denies fork, Mach
 * lookups, POSIX IPC and signals to other processes, so the limits cover the
 * one helper process; a shell helper can run builtins only. macOS refuses a
 * useful RLIMIT_AS and only sends SIGXCPU at RLIMIT_CPU, so there the parent
 * enforces max_address_bytes on the physical footprint and max_cpu_seconds
 * (plus 250 ms) on CPU time, sampled every 10 ms (SIGKILL; one interval of
 * overshoot). On Linux and macOS, RLIMIT_FSIZE caps each file at
 * max_tree_bytes during the run, and the regular files below root must total
 * at most max_tree_bytes before launch, every 10 ms while the helper runs
 * (SIGKILL to its process group; one interval of overshoot) and after exit
 * (TREE_LIMIT otherwise; the same check as the Linux filesystem jail). The
 * parent walks the tree, outside the sandbox. On macOS the walk shares the
 * 10 ms loop with the footprint and CPU checks, so a large tree lengthens the
 * interval for all three. Linux confinement does not restrict the
 * filesystem, so a file written outside root is bounded only by
 * RLIMIT_FSIZE. Windows uses a
 * zero-capability AppContainer, private staged files, a one-process Job with
 * memory/CPU/wall limits and an explicit stdio handle allowlist. max_nofile
 * is a POSIX descriptor quota; Windows bounds inherited handles and process
 * memory, not the number of later OS handle allocations. No environment
 * credentials or inherited RPC/wallet descriptors cross exec. Wall timeout
 * kills only this invocation's dedicated process group. A CLOEXEC error
 * pipe distinguishes setup/exec failures from a helper that exits 126.
 * Paths must be absolute, inside root, and free of symbolic links.
 * A successful launch is local execution evidence, not release qualification.
 */
struct SwarmConfineRequest {
    fs::path helper;
    fs::path root;
    int64_t max_address_bytes{0};
    int max_cpu_seconds{0};
    int max_nofile{0};
    bool network_denied{false};
    int max_wall_seconds{60};
    uint64_t max_tree_bytes{1024ULL * 1024 * 1024};
};

struct SwarmConfineResult {
    bool launched{false};
    bool limits_applied{false};
    int child_status{-1};
    std::string code;
};

SwarmConfineResult SwarmRunConfined(const SwarmConfineRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CONFINE_H
