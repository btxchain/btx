// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RELEASE_H
#define BITCOIN_MODELNET_RELEASE_H

#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** One confirmed-or-submitted htlc_sha256 funding output for a campaign. */
struct ReleaseFundingOutpoint {
    std::string txid;
    uint32_t vout{0};
    std::string output_script_hex;
    int64_t amount_atoms{0};
};

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
    std::vector<ReleaseFundingOutpoint> funding_outpoints; // recorded when submitmodelfunding succeeds
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

/** Most campaigns a CampaignIndex holds; the search index and the feed hold as many records. */
constexpr size_t CAMPAIGN_INDEX_CAP_DEFAULT = 100000;
/** At the cap, the most campaigns that must stay one insert moves aside before it skips the new campaign. */
constexpr size_t CAMPAIGN_INDEX_KEPT_SCAN = 64;

/** True when this node added something to `c` that no search record carries:
 *  a key or signature, a pledge, a funding script, outpoint or observation, or an unlock. */
bool CampaignHasLocalState(const ReleaseCampaign& c);

class CampaignIndex {
public:
    /** True for a campaign the index must not drop (for example one this node created). */
    using KeepFn = std::function<bool(const ReleaseCampaign&)>;

private:
    std::map<std::string, ReleaseCampaign> m_by_release;
    std::map<std::string, std::string> m_model_to_release;
    /** When a record last named each campaign (or the cap passed over it because it must stay), oldest first:
     *  the order campaigns are dropped at the cap. */
    std::map<uint64_t, std::string> m_by_age;
    std::map<std::string, uint64_t> m_age;
    uint64_t m_next_age{0};
    size_t m_cap{CAMPAIGN_INDEX_CAP_DEFAULT};

    bool Droppable(const ReleaseCampaign& c, const KeepFn& keep) const;
    void Touch(const std::string& release_hex);
    void Erase(const std::string& release_hex);

public:
    bool Put(const ReleaseCampaign& c, std::string& err);
    const ReleaseCampaign* GetByRelease(const Digest48& release_id) const;
    const ReleaseCampaign* GetByReleaseHex(const std::string& hex) const;
    const ReleaseCampaign* GetByModel(const Digest48& model_id) const;
    /** First campaign, in release id order, that `match` accepts. Copies nothing. */
    const ReleaseCampaign* Find(const std::function<bool(const ReleaseCampaign&)>& match) const;
    std::vector<ReleaseCampaign> List() const;
    size_t Size() const { return m_by_release.size(); }
    void SetCap(size_t cap) { m_cap = cap; }
    void Clear()
    {
        m_by_release.clear();
        m_model_to_release.clear();
        m_by_age.clear();
        m_age.clear();
    }
    /**
     * Learn the campaign a search record names. The search index has just
     * taken `r` as its model's record, so a campaign learned from that model's
     * earlier record is dropped. At the cap the campaign no record has named
     * for longest is dropped first. One that must stay is moved to the newest
     * end instead, and after CAMPAIGN_INDEX_KEPT_SCAN of those the new
     * campaign is skipped until its record is ingested again. A campaign
     * stays when `keep` says so or CampaignHasLocalState() holds.
     */
    void IngestFromSearchRecord(const struct ModelSearchRecord& r, const KeepFn& keep = {});
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RELEASE_H
