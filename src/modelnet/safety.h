// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SAFETY_H
#define BITCOIN_MODELNET_SAFETY_H

#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace modelnet {

/** Operator-pinned safety publishers. Not consensus, BanMan, AddrMan, or spend. */
constexpr size_t MAX_SAFETY_PUBLISHERS = 64;
constexpr size_t MAX_SAFETY_ADVISORIES = 4096;
constexpr size_t MAX_SAFETY_WARNINGS = 256;
constexpr size_t MAX_CATALOG_MODELS = 4096;

constexpr uint8_t SAFETY_TARGET_MODEL = 1;
constexpr uint8_t SAFETY_TARGET_ARTIFACT = 2;
constexpr uint8_t SAFETY_TARGET_DIGEST = 3;

constexpr uint8_t SAFETY_MALWARE = 1;
constexpr uint8_t SAFETY_UNSAFE_EXEC = 2;
constexpr uint8_t SAFETY_SPAM = 3;
constexpr uint8_t SAFETY_GARBAGE = 4;

/** Name/path skip list used by import, retrieve manifests, and watch. */
bool RelPathLooksUnsafe(const std::string& rel);

class SafetyRegistry {
public:
    struct Advisory {
        std::string publisher_id;
        std::string record_id;
        std::string target_id;
        uint8_t target_kind{SAFETY_TARGET_MODEL};
        uint8_t severity{SAFETY_MALWARE};
        uint16_t reason_code{0};
        std::string content_sha384;
        std::string note;
        int64_t expires_at{0};
        bool local{false};
    };

private:
    mutable std::mutex m_mu;
    fs::path m_dir;
    std::unordered_map<std::string, std::string> m_publishers;
    std::vector<Advisory> m_advisories;
    std::vector<Advisory> m_warnings;
    std::unordered_set<std::string> m_deny;
    std::unordered_set<std::string> m_quarantine;

    void RebuildLocked(int64_t now);
    bool PersistLocked(std::string& err) const;
    void LoadLocked();

public:
    void Bind(const fs::path& helper_dir);
    void ResetForTests();

    bool PinPublisher(const std::string& publisher_id_hex, const std::string& label, std::string& err);
    bool UnpinPublisher(const std::string& publisher_id_hex);
    bool PublisherPinned(const std::string& publisher_id_hex) const;

    bool LocalReport(const std::string& target_hex, uint8_t target_kind, uint8_t severity,
                     const std::string& note, int64_t now, std::string& err);
    bool IngestSigned(const UniValue& body, const std::string& signer_id, const std::string& record_id,
                      int64_t now, bool& applied, std::string& err);

    bool SubjectBlocked(const std::string& hex_id) const;
    bool SubjectQuarantined(const std::string& hex_id) const;

    UniValue PublishersJson() const;
    UniValue AdvisoriesJson(int64_t now) const;
    UniValue WarningsJson(int64_t now) const;
};

SafetyRegistry& GlobalSafety();
void EnsureSafetyBound(const fs::path& helper_dir);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SAFETY_H
