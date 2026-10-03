// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MATMUL_COMPUTE_QUALIFICATION_H
#define BITCOIN_MATMUL_COMPUTE_QUALIFICATION_H

#include <primitives/block.h>
#include <uint256.h>
#include <util/fs.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class UniValue;

namespace pwc {

inline constexpr uint32_t kQualEpisodeMin = 1;
inline constexpr uint32_t kQualEpisodeMax = 16;
inline constexpr size_t kQualRegistryMax = 4096;

struct QualificationFreshness {
    std::string network;
    std::string profile_name;
    std::array<unsigned char, 32> subject{};
    std::array<unsigned char, 32> issuer_nonce{};
    int64_t issued_at_ms{0};
    int64_t expires_at_ms{0};
    uint32_t episode_count{0};
    int32_t anchor_height{0};
    uint256 anchor_hash{};
    uint64_t max_elapsed_ms{0};
};

std::array<unsigned char, 48> ChallengeId(const QualificationFreshness& in);
CBlockHeader EpisodeHeader(const std::array<unsigned char, 48>& challenge_id, uint32_t episode_index);

bool IssueQualification(const QualificationFreshness& in, bool allow_test, UniValue& challenge, std::string& err_code, std::string& err);

/** Local exact work. Production profile execution requires allow_production.
 *  `backend` is cpu, or auto/cuda/hip/metal/ascend. A named device that is
 *  not self-qualified fails closed. The issuer still recomputes on the CPU
 *  reference. */
bool SolveQualification(const UniValue& challenge, uint64_t time_budget_ms, bool allow_production,
                        UniValue& response, std::string& err_code, std::string& err,
                        const std::string& backend = "cpu");

class QualificationRegistry {
public:
    bool Open(const fs::path& path, std::string& err);
    bool Healthy() const { return m_healthy; }
    UniValue Health() const;
    bool RememberIssued(const UniValue& challenge, std::string& err_code, std::string& err);
    bool Verify(const UniValue& challenge, const UniValue& response, bool redeem, int64_t now_ms,
                UniValue& out, std::string& err_code, std::string& err);
    bool Status(const std::string& challenge_id, int64_t now_ms, UniValue& out, std::string& err_code, std::string& err);

private:
    struct Entry {
        std::string id;
        std::string profile_id;
        std::string subject;
        int64_t issued_at_ms{0};
        int64_t expires_at_ms{0};
        uint32_t episode_count{0};
        uint64_t max_elapsed_ms{0};
        bool redeemed{false};
        int64_t redeemed_at_ms{0};
        std::string canonical;
    };
    fs::path m_path;
    bool m_healthy{false};
    std::string m_error;
    fs::path m_quarantine;
    std::vector<Entry> m_entries;

    bool Load(std::string& err);
    bool Save(std::string& err);
    Entry* Find(const std::string& id);
};

} // namespace pwc

#endif
