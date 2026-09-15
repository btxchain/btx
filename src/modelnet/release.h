// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RELEASE_H
#define BITCOIN_MODELNET_RELEASE_H

#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** Campaign coordination only. Monetary claim/refund uses 0.34.6 htlc_sha256 + buildhtlcclaim/buildhtlcrefund. */
struct ReleaseCampaign {
    Digest48 release_id;
    Digest48 model_id;
    Digest48 artifact_id;
    Hash32 key_hash; // SHA256(secret), never HASH160
    int64_t target_atoms{0};
    int64_t pledged_atoms{0};
    int64_t funded_atoms{0}; // helper-local observation; not chain-confirmed
    uint32_t refund_height{0};
    uint32_t latest_funding_height{0};
    int64_t campaign_created_at{0};
    bool frozen{false};
    bool secret_disclosed{false};
    bool plaintext_verified{false};
    std::string assurance{"KEY_RELEASE_ONLY"};
    std::string hashlock_algorithm{"SHA256"};
    Digest48 ciphertext_artifact_id;
    std::string output_script_hex; // P2MR scriptPubKey; hashlock is not in the program bytes
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> sig;
    bool signed_ok{false};
};

struct ReleaseStateObservation {
    Digest48 release_id;
    std::string state;
    int64_t funded_atoms_observed{0};
    bool confirmed_known{false};
    uint32_t chain_height{0};
    std::string claim_txid;
    int64_t observed_at{0};
    std::string observer_id;
    std::string funding_source{"OBSERVED_NETWORK_STATE"};
};

Hash32 ReleaseHash(Span<const unsigned char> secret32);
bool ValidRefundWindow(uint32_t latest_funding, uint32_t min_conf, uint32_t claim_margin, uint32_t refund_height);
bool RejectHash160Campaign(const UniValue& options, std::string& err);
std::vector<unsigned char> ReleaseStaticPreimage(const ReleaseCampaign& c);
bool SignReleaseCampaign(ReleaseCampaign& c, Span<const unsigned char> sk, std::string& err);
bool VerifyReleaseCampaign(const ReleaseCampaign& c, std::string& err);
UniValue CampaignToJson(const ReleaseCampaign& c);
bool CampaignFromJson(const UniValue& o, ReleaseCampaign& c, std::string& err);
bool LoadCampaigns(const fs::path& dir, std::vector<ReleaseCampaign>& out, std::string& err);
bool SaveCampaigns(const fs::path& dir, const std::vector<ReleaseCampaign>& campaigns, std::string& err);

class CampaignIndex {
    std::map<std::string, ReleaseCampaign> m_by_release;
    std::map<std::string, std::string> m_model_to_release;

public:
    bool Put(const ReleaseCampaign& c, std::string& err);
    const ReleaseCampaign* GetByRelease(const Digest48& release_id) const;
    const ReleaseCampaign* GetByReleaseHex(const std::string& hex) const;
    const ReleaseCampaign* GetByModel(const Digest48& model_id) const;
    std::vector<ReleaseCampaign> List() const;
    size_t Size() const { return m_by_release.size(); }
    void Clear()
    {
        m_by_release.clear();
        m_model_to_release.clear();
    }
    void IngestFromSearchRecord(const struct ModelSearchRecord& r);
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RELEASE_H
