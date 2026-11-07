// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_NET_KIND_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_NET_KIND_H

#include <modelnet/swarm_sandboxgate/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * How one Net attempt relates to the stored grants.
 * Permit is a policy result. It does not open a socket. The book is not modified.
 */
enum class SwarmSandboxGateNetKind {
    Permit,
    Net,
    NotGranted,
    Expired,
    NetDenied,
};

/**
 * Classify one Net attempt.
 * An empty host_id is Net.
 * An unknown worker is NotGranted.
 * A live grant with network set is Permit.
 * When every grant is expired, or every network grant is expired while
 * another grant is still live, the result is Expired.
 * A worker with no network grant and a live grant is NetDenied.
 */
SwarmSandboxGateNetKind SwarmSandboxGateClassifyNet(const SwarmSandboxGateBook& book,
                                                    const std::string& worker,
                                                    const std::string& host_id,
                                                    int64_t now_ms);

/**
 * Refusal code for a non-permit kind, or nullptr for Permit.
 */
const char* SwarmSandboxGateNetKindCode(SwarmSandboxGateNetKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_NET_KIND_H
