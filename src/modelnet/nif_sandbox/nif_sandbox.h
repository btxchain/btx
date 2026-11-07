// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_SANDBOX_NIF_SANDBOX_H
#define BITCOIN_MODELNET_NIF_SANDBOX_NIF_SANDBOX_H

#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** One directory root. A path outside that root is not read. */
class NifSandbox {
public:
    bool Bind(const fs::path& root, std::string& err);
    bool OpenPath(const fs::path& path, std::string& err);
    bool Egress(const std::string& host, std::string& err);
    bool Download(const std::string& url, std::string& err);
    bool LoadCheckpoint(const std::vector<unsigned char>& body, std::string& err);
    bool SpawnChild(std::string& err);

    const std::vector<unsigned char>& opened() const { return m_opened; }
    const std::vector<unsigned char>& data() const { return m_data; }
    int64_t bytes_read() const { return m_bytes_read; }
    int64_t startup_downloads() const { return m_startup_downloads; }
    int64_t child_count() const { return static_cast<int64_t>(m_slots.size()); }
    bool egress_opened() const { return false; }
    bool executable() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool OpenInside(const fs::path& normal, std::string& err);
    bool ReadFile(const fs::path& path, std::string& err);

    fs::path m_root;
    std::string m_root_utf8;
    std::vector<unsigned char> m_opened;
    std::vector<unsigned char> m_data;
    std::vector<std::uint64_t> m_slots;
    int64_t m_bytes_read{0};
    int64_t m_startup_downloads{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_SANDBOX_NIF_SANDBOX_H
