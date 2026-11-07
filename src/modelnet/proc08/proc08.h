// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC08_PROC08_H
#define BITCOIN_MODELNET_PROC08_PROC08_H

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

/**
 * Proc08. ASR-CAP-002 reads regular files from a caller-supplied directory
 * and stores one combined FNV-1a 64-bit hex digest. release_qualified()
 * stays false after a successful read. A temporary directory does not
 * qualify a release.
 * ASR-PUB-001 accepts a research path only when that path exists and is
 * neither the worktree root nor the root followed by a slash and a suffix.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * This class opens no socket and starts no process.
 */
class Proc08 {
public:
    bool ReadEvidence(const std::string& dir, std::string& err);
    bool AcceptResearchPath(const std::string& path, const std::string& worktree_root, std::string& err);

    std::string digest() const { return m_digest; }
    int files_hashed() const { return m_files; }
    bool research_outside() const { return m_research_outside; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::string m_digest;
    int m_files{0};
    bool m_research_outside{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROC08_PROC08_H
