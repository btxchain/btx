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
#include <exception>
#include <fstream>
#include <iostream>

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

namespace {

void LogSkippedCampaign(const std::string& why)
{
    std::cerr << "btx-modeld: skipped malformed feed object (" << why << ")\n";
}

bool CampaignTypeFail(std::string& err, const std::string& why)
{
    err = why;
    LogSkippedCampaign(why);
    return false;
}

bool CampaignStr(const UniValue& o, const char* k, std::string& dst, std::string& err, bool required)
{
    if (!o.exists(k)) {
        if (required) {
            err = k;
            return false;
        }
        return true;
    }
    if (!o[k].isStr()) return CampaignTypeFail(err, std::string(k) + " type");
    dst = o[k].get_str();
    return true;
}

template <typename Int>
bool CampaignInt(const UniValue& o, const char* k, Int& dst, std::string& err)
{
    if (!o.exists(k)) return true;
    if (!o[k].isNum()) return CampaignTypeFail(err, std::string(k) + " type");
    try {
        dst = o[k].getInt<Int>();
    } catch (const std::exception&) {
        return CampaignTypeFail(err, std::string(k) + " range");
    }
    return true;
}

bool CampaignBool(const UniValue& o, const char* k, bool& dst, std::string& err)
{
    if (!o.exists(k)) return true;
    if (!o[k].isBool()) return CampaignTypeFail(err, std::string(k) + " type");
    dst = o[k].get_bool();
    return true;
}

} // namespace

bool CampaignFromJson(const UniValue& o, ReleaseCampaign& c, std::string& err)
{
    c = {};
    if (!o.isObject()) {
        err = "object";
        return false;
    }
    ReleaseCampaign parsed;
    try {
        std::string release_id;
        if (!CampaignStr(o, "release_id", release_id, err, true)) return false;
        if (!Digest48::FromHex(release_id, parsed.release_id, err)) return false;
        std::string hex;
        if (!CampaignStr(o, "model_id", hex, err, false)) return false;
        if (!hex.empty() && !Digest48::FromHex(hex, parsed.model_id, err)) return false;
        hex.clear();
        if (!CampaignStr(o, "artifact_id", hex, err, false)) return false;
        if (!hex.empty() && !Digest48::FromHex(hex, parsed.artifact_id, err)) return false;
        hex.clear();
        if (!CampaignStr(o, "ciphertext_artifact_id", hex, err, false)) return false;
        if (!hex.empty() && !Digest48::FromHex(hex, parsed.ciphertext_artifact_id, err)) return false;
        hex.clear();
        if (!CampaignStr(o, "key_hash", hex, err, false)) return false;
        if (!hex.empty() && !Hash32::FromHex(hex, parsed.key_hash, err)) return false;
        if (!CampaignInt(o, "target_atoms", parsed.target_atoms, err) ||
            !CampaignInt(o, "pledged_atoms", parsed.pledged_atoms, err) ||
            !CampaignInt(o, "funded_atoms", parsed.funded_atoms, err) ||
            !CampaignInt(o, "refund_height", parsed.refund_height, err) ||
            !CampaignInt(o, "latest_funding_height", parsed.latest_funding_height, err) ||
            !CampaignInt(o, "campaign_created_at", parsed.campaign_created_at, err) ||
            !CampaignBool(o, "frozen", parsed.frozen, err) ||
            !CampaignBool(o, "secret_disclosed", parsed.secret_disclosed, err) ||
            !CampaignBool(o, "plaintext_verified", parsed.plaintext_verified, err) ||
            !CampaignStr(o, "assurance", parsed.assurance, err, false) ||
            !CampaignStr(o, "hashlock_algorithm", parsed.hashlock_algorithm, err, false)) {
            return false;
        }
        if (o.exists("output_script")) {
            if (!o["output_script"].isStr()) return CampaignTypeFail(err, "output_script type");
            parsed.output_script_hex = ToLower(o["output_script"].get_str());
        }
        if (o.exists("pubkey")) {
            if (!o["pubkey"].isStr()) return CampaignTypeFail(err, "pubkey type");
            parsed.pubkey = ParseHex(o["pubkey"].get_str());
        }
        if (o.exists("signature")) {
            if (!o["signature"].isStr()) return CampaignTypeFail(err, "signature type");
            parsed.sig = ParseHex(o["signature"].get_str());
        }
    } catch (const std::exception& ex) {
        c = {};
        return CampaignTypeFail(err, ex.what());
    } catch (...) {
        c = {};
        return CampaignTypeFail(err, "malformed campaign");
    }
    parsed.signed_ok = !parsed.sig.empty();
    if (parsed.ciphertext_artifact_id.IsNull()) parsed.ciphertext_artifact_id = parsed.artifact_id;
    if (parsed.hashlock_algorithm.empty()) parsed.hashlock_algorithm = "SHA256";
    if (parsed.assurance.empty()) parsed.assurance = "KEY_RELEASE_ONLY";
    c = std::move(parsed);
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
    if (!o["campaigns"].isArray()) {
        LogSkippedCampaign("campaigns type");
        return true;
    }
    try {
        for (const auto& cj : o["campaigns"].getValues()) {
            ReleaseCampaign c;
            std::string ierr;
            try {
                if (!CampaignFromJson(cj, c, ierr)) {
                    LogSkippedCampaign(ierr.empty() ? "campaign" : ierr);
                    continue;
                }
            } catch (const std::exception& ex) {
                LogSkippedCampaign(ex.what());
                continue;
            } catch (...) {
                LogSkippedCampaign("campaign");
                continue;
            }
            out.push_back(std::move(c));
        }
    } catch (const std::exception& ex) {
        LogSkippedCampaign(ex.what());
        err = ex.what();
        return true;
    } catch (...) {
        err = "campaigns";
        LogSkippedCampaign(err);
        return true;
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
