// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_CONTRIB_RC_PROVER_TOKEN_ACL_APPLE_H
#define BITCOIN_CONTRIB_RC_PROVER_TOKEN_ACL_APPLE_H

#include <sys/types.h>
#include <sys/acl.h>
#include <cerrno>
#include <stdexcept>

namespace rc_prover {
inline void CheckAppleTokenAcl(int fd)
{
    errno = 0;
    const acl_t acl{acl_get_fd_np(fd, ACL_TYPE_EXTENDED)};
    if (acl == nullptr) {
        // Darwin filesec reports an absent ACL property as ENOENT on this fd.
        if (errno == ENOENT) return;
        throw std::runtime_error("cannot inspect token-file extended ACL");
    }
    struct FreeAcl { acl_t value; ~FreeAcl() { acl_free(value); } } free_acl{acl};
    if (acl_valid(acl) != 0) throw std::runtime_error("invalid token-file extended ACL");
    acl_entry_t entry{};
    errno = 0;
    const int result{acl_get_entry(acl, ACL_FIRST_ENTRY, &entry)};
    const int error{errno};
    // Darwin returns 0 for an entry, -1/EINVAL for an empty valid ACL.
    // Reject every entry, including inherited, owner-only and deny entries:
    // do not attempt to reconstruct effective rights from mode bits.
    if (result == 0) throw std::runtime_error("token file must have no extended ACL entries");
    if (result != -1 || error != EINVAL) throw std::runtime_error("cannot enumerate token-file extended ACL");
}
} // namespace rc_prover
#endif
