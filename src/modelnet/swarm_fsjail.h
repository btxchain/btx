// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FSJAIL_H
#define BTX_MODELNET_SWARM_FSJAIL_H

#include <util/fs.h>

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * Execute a helper in a filesystem and network sandbox. Linux unshares user,
 * mount AND network namespaces, installs uid/gid maps, then pivot_roots into
 * root. If pivot_root fails, the helper does not run (JAIL_ABSENT).
 * macOS uses default-deny Seatbelt, allowing the selected root and read-only
 * system libraries required to launch a native executable. It denies host
 * user data, arbitrary process creation, IPC and all network access.
 * Windows uses a private staged AppContainer profile with no network
 * capabilities and a one-process resource-bounded Job. Owner ACLs remain
 * unchanged; only fresh output files are copied back after inputs reverify.
 * OS system resources and the private profile are platform exceptions.
 * A CLOEXEC error pipe proves setup and exec; child exit 126 is not confused
 * with failure to install the sandbox. Paths reject symlinks and traversal.
 * Limits and a wall timeout apply. On Linux and macOS, RLIMIT_FSIZE caps
 * each file at max_tree_bytes, and the regular files below root must total at
 * most max_tree_bytes before launch, every 10 ms while the helper runs and
 * after exit (TREE_LIMIT otherwise), as in SwarmRunConfined.
 * Neither success nor compile qualifies a platform release; native escape and
 * workload tests must run on that OS.
 */
struct SwarmFilesystemJailRequest {
    fs::path helper;
    fs::path root;
    bool network_denied{false};
    int max_wall_seconds{60};
    uint64_t max_tree_bytes{1024ULL * 1024 * 1024};
};

struct SwarmFilesystemJailResult {
    bool launched{false};
    bool jailed{false};
    std::string code;
    int child_status{-1};
};

SwarmFilesystemJailResult SwarmRunFilesystemJail(const SwarmFilesystemJailRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FSJAIL_H
