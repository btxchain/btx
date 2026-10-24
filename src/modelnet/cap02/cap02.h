// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CAP02_CAP02_H
#define BITCOIN_MODELNET_CAP02_CAP02_H

#include <modelnet/nifdt_contract/contract.h>

#include <string>
#include <vector>
#include <cstdint>

namespace modelnet {

struct NativeToolFile {
    std::string relative_path;
    std::string sha384;
    uint64_t bytes{0};
};
/** Owner-installed policy. Never populate executable or expected outputs
 * directly from peer-supplied cards. The executable must be in files. */
struct NativeToolProbe {
    std::string root;
    std::string executable;
    std::vector<NativeToolFile> files;
    std::string output_relative_path;
    std::string expected_output_sha384;
    uint64_t expected_output_bytes{0};
    uint64_t max_package_bytes{1024ULL * 1024 * 1024};
    int wall_seconds{60};
};
struct NativeToolEvidence {
    std::string package_sha384;
    std::string executable_sha384;
    std::string output_sha384;
    std::string operating_system;
    std::string architecture;
    int64_t elapsed_ms{0};
    int exit_code{-1};
};

/**
 * Legacy Qualify verifies manifest integrity only. QualifyNative verifies an
 * owner-pinned package, starts its actual probe inside the OS filesystem and
 * network sandbox, requires exit zero and newly produced exact result bytes,
 * then rechecks all pinned inputs. Evidence describes the observed platform;
 * a caller cannot claim a different OS. It does not qualify the whole node.
 */
class Cap02 {
public:
    bool Qualify(const std::string& dir, std::string& err);
    bool QualifyNative(const NativeToolProbe& probe, std::string& err);
    const NativeToolEvidence& native_evidence() const { return m_evidence; }
    bool native_qualified() const { return m_native; }

    int files_checked() const { return m_files; }
    bool passed() const { return m_native; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    int m_files{0};
    bool m_native{false};
    NativeToolEvidence m_evidence;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_CAP02_CAP02_H
