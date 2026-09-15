// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/release.h>

#include <crypto/common.h>
#include <modelnet/crypto.h>
#include <modelnet/identity.h>
#include <modelnet/search.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>

namespace modelnet {
namespace {

void PutU16(std::vector<unsigned char>& b, uint16_t v)
{
    unsigned char t[2];
    WriteLE16(t, v);
    b.insert(b.end(), t, t + 2);
}
void PutU32(std::vector<unsigned char>& b, uint32_t v)
{
    unsigned char t[4];
    WriteLE32(t, v);
    b.insert(b.end(), t, t + 4);
}
void PutU64(std::vector<unsigned char>& b, uint64_t v)
{
    unsigned char t[8];
    WriteLE64(t, v);
    b.insert(b.end(), t, t + 8);
}
void PutStr(std::vector<unsigned char>& b, const std::string& s)
{
    const uint16_t n = static_cast<uint16_t>(std::min(s.size(), size_t{4096}));
    PutU16(b, n);
    b.insert(b.end(), s.begin(), s.begin() + n);
}

} // namespace

Hash32 ReleaseHash(Span<const unsigned char> secret32)
{
    return Sha256(secret32);
}

bool ValidRefundWindow(uint32_t latest_funding, uint32_t min_conf, uint32_t claim_margin, uint32_t refund_height)
{
    if (!(latest_funding > 0 && latest_funding < refund_height && refund_height < 500000000u)) return false;
    return latest_funding + min_conf + claim_margin < refund_height;
}

bool RejectHash160Campaign(const UniValue& options, std::string& err)
{
    if (!options.isObject()) return true;
    auto bad = [&](const std::string& s) {
        const std::string x = ToLower(s);
        return x.find("hash160") != std::string::npos || x.find("htlc_tx") != std::string::npos ||
               x == "ripemd160";
    };
    for (const char* k : {"hashlock_algorithm", "algorithm", "htlc", "template", "htlc_template"}) {
        if (options.exists(k) && options[k].isStr() && bad(options[k].get_str())) {
            err = "HASH160 campaign creation is rejected; new campaigns use SHA-256 KEY_RELEASE_ONLY";
            return false;
        }
    }
    return true;
}

std::vector<unsigned char> ReleaseStaticPreimage(const ReleaseCampaign& c)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), c.release_id.data.begin(), c.release_id.data.end());
    b.insert(b.end(), c.model_id.data.begin(), c.model_id.data.end());
    b.insert(b.end(), c.artifact_id.data.begin(), c.artifact_id.data.end());
    b.insert(b.end(), c.key_hash.data.begin(), c.key_hash.data.end());
    PutU64(b, static_cast<uint64_t>(c.target_atoms));
    PutU32(b, c.refund_height);
    PutU32(b, c.latest_funding_height);
    PutU64(b, static_cast<uint64_t>(c.campaign_created_at));
    PutStr(b, c.assurance.empty() ? "KEY_RELEASE_ONLY" : c.assurance);
    b.insert(b.end(), c.ciphertext_artifact_id.data.begin(), c.ciphertext_artifact_id.data.end());
    return b;
}

bool SignReleaseCampaign(ReleaseCampaign& c, Span<const unsigned char> sk, std::string& err)
{
    if (c.hashlock_algorithm != "SHA256" && !c.hashlock_algorithm.empty()) {
        err = "HASH160 campaign creation is rejected";
        return false;
    }
    c.hashlock_algorithm = "SHA256";
    c.assurance = "KEY_RELEASE_ONLY";
    if (c.pubkey.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    const auto pre = ReleaseStaticPreimage(c);
    const Digest48 h = DomainHash("BTX/ReleaseStatic/v1", Span<const unsigned char>{pre.data(), pre.size()});
    return SignMlDsa44(sk, Span<const unsigned char>{h.data.data(), h.data.size()}, c.sig, err);
}

bool VerifyReleaseCampaign(const ReleaseCampaign& c, std::string& err)
{
    if (c.pubkey.empty() || c.sig.empty()) {
        err = "unsigned";
        return false;
    }
    const auto pre = ReleaseStaticPreimage(c);
    const Digest48 h = DomainHash("BTX/ReleaseStatic/v1", Span<const unsigned char>{pre.data(), pre.size()});
    if (!VerifyMlDsa44(Span<const unsigned char>{c.pubkey.data(), c.pubkey.size()},
                         Span<const unsigned char>{h.data.data(), h.data.size()},
                         Span<const unsigned char>{c.sig.data(), c.sig.size()})) {
        err = "bad campaign signature";
        return false;
    }
    return true;
}

UniValue CampaignToJson(const ReleaseCampaign& c)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("release_id", c.release_id.Hex());
    o.pushKV("model_id", c.model_id.Hex());
    o.pushKV("artifact_id", c.artifact_id.Hex());
    o.pushKV("ciphertext_artifact_id", c.ciphertext_artifact_id.IsNull() ? c.artifact_id.Hex() : c.ciphertext_artifact_id.Hex());
    if (!c.output_script_hex.empty()) o.pushKV("output_script", c.output_script_hex);
    o.pushKV("key_hash", c.key_hash.Hex());
    o.pushKV("hashlock_algorithm", "SHA256");
    o.pushKV("assurance", c.assurance.empty() ? "KEY_RELEASE_ONLY" : c.assurance);
    o.pushKV("target_atoms", c.target_atoms);
    o.pushKV("pledged_atoms", c.pledged_atoms);
    o.pushKV("funded_atoms", c.funded_atoms);
    o.pushKV("refund_height", static_cast<int64_t>(c.refund_height));
    o.pushKV("latest_funding_height", static_cast<int64_t>(c.latest_funding_height));
    o.pushKV("campaign_created_at", c.campaign_created_at);
    o.pushKV("frozen", c.frozen);
    o.pushKV("secret_disclosed", c.secret_disclosed);
    o.pushKV("plaintext_verified", c.plaintext_verified);
    o.pushKV("signed_static", c.signed_ok || !c.sig.empty());
    if (!c.pubkey.empty()) o.pushKV("pubkey", HexStr(c.pubkey));
    if (!c.sig.empty()) o.pushKV("signature", HexStr(c.sig));
    o.pushKV("claim", "buildmodelhtlcclaim / buildhtlcclaim with 0.34.6 htlc_sha256(key_hash, claimant)");
    o.pushKV("refund", "buildmodelhtlcrefund / buildhtlcrefund after refund_height");
    o.pushKV("note", "HASH160 htlc_tx is recovery-only. pledged_atoms is nonbinding; confirmed funded requires chain observation.");
    return o;
}

bool CampaignFromJson(const UniValue& o, ReleaseCampaign& c, std::string& err)
{
    c = {};
    if (!o.isObject()) {
        err = "object";
        return false;
    }
    if (!o.exists("release_id") || !Digest48::FromHex(o["release_id"].get_str(), c.release_id, err)) return false;
    if (o.exists("model_id") && !o["model_id"].get_str().empty() &&
        !Digest48::FromHex(o["model_id"].get_str(), c.model_id, err)) return false;
    if (o.exists("artifact_id") && !o["artifact_id"].get_str().empty() &&
        !Digest48::FromHex(o["artifact_id"].get_str(), c.artifact_id, err)) return false;
    if (o.exists("ciphertext_artifact_id") && !o["ciphertext_artifact_id"].get_str().empty() &&
        !Digest48::FromHex(o["ciphertext_artifact_id"].get_str(), c.ciphertext_artifact_id, err)) {
        return false;
    }
    if (o.exists("key_hash") && !o["key_hash"].get_str().empty() &&
        !Hash32::FromHex(o["key_hash"].get_str(), c.key_hash, err)) return false;
    c.target_atoms = o.exists("target_atoms") ? o["target_atoms"].getInt<int64_t>() : 0;
    c.pledged_atoms = o.exists("pledged_atoms") ? o["pledged_atoms"].getInt<int64_t>() : 0;
    c.funded_atoms = o.exists("funded_atoms") ? o["funded_atoms"].getInt<int64_t>() : 0;
    c.refund_height = o.exists("refund_height") ? o["refund_height"].getInt<uint32_t>() : 0;
    c.latest_funding_height = o.exists("latest_funding_height") ? o["latest_funding_height"].getInt<uint32_t>() : 0;
    c.campaign_created_at = o.exists("campaign_created_at") ? o["campaign_created_at"].getInt<int64_t>() : 0;
    c.frozen = o.exists("frozen") && o["frozen"].get_bool();
    c.secret_disclosed = o.exists("secret_disclosed") && o["secret_disclosed"].get_bool();
    c.plaintext_verified = o.exists("plaintext_verified") && o["plaintext_verified"].get_bool();
    if (o.exists("assurance")) c.assurance = o["assurance"].get_str();
    if (o.exists("hashlock_algorithm")) c.hashlock_algorithm = o["hashlock_algorithm"].get_str();
    if (o.exists("output_script") && o["output_script"].isStr()) c.output_script_hex = ToLower(o["output_script"].get_str());
    if (o.exists("pubkey")) c.pubkey = ParseHex(o["pubkey"].get_str());
    if (o.exists("signature")) c.sig = ParseHex(o["signature"].get_str());
    c.signed_ok = !c.sig.empty();
    if (c.ciphertext_artifact_id.IsNull()) c.ciphertext_artifact_id = c.artifact_id;
    if (c.hashlock_algorithm.empty()) c.hashlock_algorithm = "SHA256";
    if (c.assurance.empty()) c.assurance = "KEY_RELEASE_ONLY";
    return true;
}

bool LoadCampaigns(const fs::path& dir, std::vector<ReleaseCampaign>& out, std::string& err)
{
    out.clear();
    const fs::path path = dir / "campaigns.json";
    if (!fs::exists(path)) return true;
    std::ifstream in(path);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    if (!o.read(raw) || !o.isObject() || !o.exists("campaigns")) return true;
    for (const auto& cj : o["campaigns"].getValues()) {
        ReleaseCampaign c;
        if (!CampaignFromJson(cj, c, err)) return false;
        out.push_back(c);
    }
    return true;
}

bool SaveCampaigns(const fs::path& dir, const std::vector<ReleaseCampaign>& campaigns, std::string& err)
{
    UniValue o(UniValue::VOBJ);
    UniValue arr(UniValue::VARR);
    for (const auto& c : campaigns) arr.push_back(CampaignToJson(c));
    o.pushKV("campaigns", arr);
    std::ofstream out(dir / "campaigns.json", std::ios::trunc);
    if (!out) {
        err = "campaigns.json write";
        return false;
    }
    out << o.write() << "\n";
    return true;
}

bool CampaignIndex::Put(const ReleaseCampaign& c, std::string& err)
{
    if (c.release_id.IsNull()) {
        err = "release_id";
        return false;
    }
    const std::string rid = c.release_id.Hex();
    m_by_release[rid] = c;
    if (!c.model_id.IsNull()) m_model_to_release[c.model_id.Hex()] = rid;
    return true;
}

const ReleaseCampaign* CampaignIndex::GetByRelease(const Digest48& release_id) const
{
    return GetByReleaseHex(release_id.Hex());
}
const ReleaseCampaign* CampaignIndex::GetByReleaseHex(const std::string& hex) const
{
    auto it = m_by_release.find(hex);
    if (it == m_by_release.end()) return nullptr;
    return &it->second;
}
const ReleaseCampaign* CampaignIndex::GetByModel(const Digest48& model_id) const
{
    auto it = m_model_to_release.find(model_id.Hex());
    if (it == m_model_to_release.end()) return nullptr;
    return GetByReleaseHex(it->second);
}
std::vector<ReleaseCampaign> CampaignIndex::List() const
{
    std::vector<ReleaseCampaign> out;
    out.reserve(m_by_release.size());
    for (const auto& kv : m_by_release) out.push_back(kv.second);
    return out;
}

void CampaignIndex::IngestFromSearchRecord(const ModelSearchRecord& r)
{
    if (r.release_id.empty()) return;
    ReleaseCampaign c;
    std::string err;
    if (!Digest48::FromHex(r.release_id, c.release_id, err)) return;
    c.model_id = r.model_id;
    c.artifact_id = r.artifact_id;
    c.ciphertext_artifact_id = r.ciphertext_artifact_id.IsNull() ? r.artifact_id : r.ciphertext_artifact_id;
    c.key_hash = r.key_hash;
    c.target_atoms = r.release_target_atoms;
    c.refund_height = r.refund_height;
    c.campaign_created_at = r.campaign_created_at;
    c.assurance = r.assurance.empty() ? "KEY_RELEASE_ONLY" : r.assurance;
    auto* existing = const_cast<ReleaseCampaign*>(GetByRelease(c.release_id));
    if (existing) {
        if (existing->target_atoms == 0) existing->target_atoms = c.target_atoms;
        if (existing->key_hash.IsNull()) existing->key_hash = c.key_hash;
        if (existing->refund_height == 0) existing->refund_height = c.refund_height;
        if (existing->campaign_created_at == 0) existing->campaign_created_at = c.campaign_created_at;
        if (existing->ciphertext_artifact_id.IsNull() && !c.ciphertext_artifact_id.IsNull()) {
            existing->ciphertext_artifact_id = c.ciphertext_artifact_id;
        }
        return;
    }
    (void)Put(c, err);
}

} // namespace modelnet
