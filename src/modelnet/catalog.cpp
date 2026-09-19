// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/catalog.h>

#include <modelnet/crypto.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/resource_uri.h>
#include <modelnet/verified_manifest.h>
#include <modelnet/hello_caps.h>
#include <crypto/sha384.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>

namespace modelnet {
namespace {

FileRole RoleFromRelPath(const std::string& rel, bool& skip)
{
    skip = false;
    const auto lower = ToLower(rel);
    if (lower.starts_with(".") || lower.find("/.") != std::string::npos) {
        skip = true;
        return FileRole::WEIGHTS;
    }
    if (lower.ends_with(".pt") || lower.ends_with(".pth") || lower.ends_with(".pkl") ||
        lower.ends_with(".py") || lower.ends_with(".so") || lower.ends_with(".bin") ||
        lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".ipynb") ||
        lower.ends_with(".cu") || lower.ends_with(".sig")) {
        skip = true;
        return FileRole::WEIGHTS;
    }
    if (lower.ends_with(".safetensors") || lower.ends_with(".gguf") || lower.ends_with(".btxenc")) return FileRole::WEIGHTS;
    if (lower.find("tokenizer") != std::string::npos || lower == "vocab.json" ||
        lower == "merges.txt" || lower == "special_tokens_map.json") {
        return FileRole::TOKENIZER;
    }
    if (lower.find("license") != std::string::npos || lower == "notice" || lower == "copying") {
        return FileRole::LICENSE;
    }
    if (lower.find("readme") != std::string::npos || lower.find("model_card") != std::string::npos) {
        return FileRole::MODEL_CARD;
    }
    if (lower.ends_with(".json") || lower.ends_with(".jinja") || lower.ends_with(".txt")) {
        return FileRole::CONFIG;
    }
    skip = true;
    return FileRole::WEIGHTS;
}

UniValue CoreFileJson(const CoreFile& f)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("path", f.path);
    o.pushKV("role", FileRoleName(f.role));
    o.pushKV("size", f.size);
    o.pushKV("sha384", f.sha384.Hex());
    o.pushKV("pieces_root", f.pieces_root.Hex());
    return o;
}

bool CoreFileFromJson(const UniValue& o, CoreFile& f, std::string& err)
{
    f.path = o["path"].get_str();
    if (!FileRoleFromName(o["role"].get_str(), f.role)) {
        err = "role";
        return false;
    }
    f.size = o["size"].getInt<uint64_t>();
    return Digest48::FromHex(o["sha384"].get_str(), f.sha384, err) &&
           Digest48::FromHex(o["pieces_root"].get_str(), f.pieces_root, err);
}

Digest48 StagingId(const std::string& nonce)
{
    return DomainHash("BTX/ModelImportTmp/v1",
                      Span<const unsigned char>{reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size()});
}

/** Successful pipeline ranks BYTES_VERIFIED..SEEDING. FAILED and similar
 *  numeric values above SEEDING do not imply verified bytes. */
bool AdmissionImpliesBytesVerified(AdmissionLevel a)
{
    const auto v = static_cast<uint8_t>(a);
    return v >= static_cast<uint8_t>(AdmissionLevel::BYTES_VERIFIED) &&
           v <= static_cast<uint8_t>(AdmissionLevel::SEEDING);
}

bool AdmissionImpliesStructureVerified(AdmissionLevel a)
{
    const auto v = static_cast<uint8_t>(a);
    return v >= static_cast<uint8_t>(AdmissionLevel::STRUCTURE_VERIFIED) &&
           v <= static_cast<uint8_t>(AdmissionLevel::SEEDING);
}

} // namespace

namespace {
std::atomic<bool> g_adv_cloud{false};
std::atomic<bool> g_adv_direct{false};
} // namespace

void SetAdvertisedCloudCaps(bool cloud_attached, bool direct_cloud_seed)
{
    g_adv_cloud.store(cloud_attached);
    g_adv_direct.store(direct_cloud_seed);
}

bool GuessFileRole(const std::string& relpath, FileRole& role)
{
    bool skip = false;
    role = RoleFromRelPath(relpath, skip);
    return !skip;
}

UniValue CapabilitiesObject()
{
    UniValue c(UniValue::VOBJ);
    c.pushKV("schema_version", 2);
    c.pushKV("protocol", 2);
    c.pushKV("uri", true);
    c.pushKV("importmodel", true);
    c.pushKV("hostmodel", true);
    c.pushKV("checkmodelsetup", true);
    c.pushKV("previewmodelimport", true);
    c.pushKV("getmodelsharecard", true);
    c.pushKV("getmodeltransfers", true);
    c.pushKV("setmodelalias", true);
    c.pushKV("scanmodelwatch", true);
    c.pushKV("getmodelwatchstatus", true);
    c.pushKV("showmodel", true);
    c.pushKV("exportmodellink", true);
    c.pushKV("unhostmodel", true);
    c.pushKV("removemodelalias", true);
    c.pushKV("openmodelshare", true);
    c.pushKV("seedmodel", true);
    c.pushKV("listmodels", true);
    c.pushKV("getmodelmanifest", true);
    c.pushKV("qualifymodel", true);
    c.pushKV("getmodel_free_only", true);
    c.pushKV("pq1_http", true);
    c.pushKV("piece_wire", "application/octet-stream");
    c.pushKV("paid_retrieval", true);          // local quote journal + prepaid quote RPC
    c.pushKV("paid_chain_verify", false);      // helper journals submit; does not verify chain inclusion
    c.pushKV("paid_funding_rpc", true);        // prepare/sign/submit freeze exact htlc_sha256 round
    c.pushKV("signed_free_grant", true);
    c.pushKV("release_campaign_rpc", true);   // coordination only; not a spend
    c.pushKV("buildmodelhtlcclaim", true);
    c.pushKV("htlc_reuse", "0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund");
    c.pushKV("remote_inference", false);
    c.pushKV("cuda_qualification", true);  // isolated posix worker; QualifyFile never cudaSetDevice
    c.pushKV("browser_bridge", false);        // optional separate process, not native PQ
    c.pushKV("node_model_index", true);       // model-plane only; not a monetary NODE_* bit
    c.pushKV("searchmodels", true);
    c.pushKV("decentralized_search", true);
    c.pushKV("automatic_spend_atoms", 0);
    c.pushKV("full_file_stream_v1", true);
    c.pushKV("subpiece_v1", true);
    c.pushKV("package_v1", true);
    c.pushKV("erasure_preservation_v1", true);
    c.pushKV("query_summary_v1", true);
    c.pushKV("index_reconcile_v1", true);
    c.pushKV("metadata_gossip_v1", true);
    c.pushKV("origin_offer_v1", true);
    c.pushKV("lan_discovery_v1", true);
    c.pushKV("selective_files_v1", true);
    c.pushKV("capabilities", HelloCapabilityArray());
    c.pushKV("quic", false);
    c.pushKV("utp", "NONSHIPPING");
    c.pushKV("btx_torrentd_process", false);
    c.pushKV("cloud_attached_storage", g_adv_cloud.load());
    c.pushKV("direct_cloud_seed", g_adv_direct.load());
    c.pushKV("model_event_journal", true);
    c.pushKV("subscription_mandate", true);
    c.pushKV("demand_seed_default", true);
    c.pushKV("preserve_rare", true);
    c.pushKV("follow_configured_peers_default", true);
    c.pushKV("unsolicited_fetch_default", false);
    c.pushKV("extension_version", 257);
    // Native helper bits: RESOURCE_RESOLVE|FREE_GRANT|SERVICE_RECEIPT|RESEARCH_IDENTITY|
    // COLLECTIONS_ALIAS|POLICY_BUNDLE|PRESERVATION_CIRCLE. Signed announce, typed
    // resolve, receipts, collections/circles and jitter exist; paid_chain_verify remains false.
    c.pushKV("features", 127);
    UniValue http(UniValue::VARR);
    for (const char* p : {
             "POST /hello", "POST /query", "POST /records/get", "POST /records/announce",
             "GET /manifests/{id}", "POST /availability", "POST /quotes",
             "POST /transfers/{id}/payment", "GET /transfers/{id}/pieces/{file}/{piece}",
             "GET /files/{artifact}/{file}",
             "POST /releases/{id}/pledges", "POST /releases/{id}/rounds", "POST /releases/{id}/signatures",
             "POST /ext/caps", "POST /ext/resolve", "POST /ext/objects/get", "POST /ext/objects/announce",
             "POST /ext/free/grant", "POST /ext/receipts",
             "POST /ext/pex", "POST /ext/rendezvous", "POST /ext/relay/connect",
             "POST /ext/autonat/probe", "POST /ext/autonat/report", "POST /ext/relay/reserve",
             "POST /ext/holepunch",              "POST /ext/providers/put", "POST /ext/providers/get",
             "POST /ext/search", "POST /ext/feed"}) {
        http.push_back(p);
    }
    c.pushKV("http", http);
    return c;
}

bool ImportRegularFile(ModelStore& store, const Digest48& staging_artifact, uint32_t file_index,
                       const fs::path& src, const std::string& relpath, CoreFile& out,
                       QualReport* qual, std::string& err)
{
    out = {};
    out.path = relpath;
    if (!IsPortableRelPath(relpath, err)) return false;
    bool skip = false;
    out.role = RoleFromRelPath(relpath, skip);
    if (skip) {
        err = "skipped unsafe or unsupported name";
        return false;
    }

    const std::string srcs = fs::PathToString(src);
    if (out.role == FileRole::WEIGHTS) {
        QualReport report;
        const auto qr = QualifyFile(srcs, report);
        if (qual) *qual = report;
        if (qr == QualResult::REJECTED_UNSAFE_FORMAT || qr == QualResult::INVALID_MODEL) {
            err = report.detail;
            return false;
        }
    }

    std::ifstream in(src, std::ios::binary);
    if (!in) {
        err = "cannot open " + srcs;
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff sz = in.tellg();
    if (sz < 0) {
        err = "stat failed";
        return false;
    }
    out.size = static_cast<uint64_t>(sz);
    in.seekg(0);

    CSHA384 hasher;
    std::vector<Digest48> real_leaves;
    std::vector<unsigned char> buf(PIECE_SIZE);
    uint32_t piece_index = 0;
    uint64_t remaining = out.size;
    while (remaining > 0) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(PIECE_SIZE, remaining));
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n));
        if (static_cast<size_t>(in.gcount()) != n) {
            err = "short read";
            return false;
        }
        hasher.Write(buf.data(), n);
        Span<const unsigned char> piece{buf.data(), n};
        const Digest48 leaf = ChunkLeaf(piece_index, piece);
        if (!store.PutVerifiedPiece(staging_artifact, file_index, piece_index, piece, leaf, err)) {
            return false;
        }
        real_leaves.push_back(leaf);
        remaining -= n;
        ++piece_index;
    }
    hasher.Finalize(out.sha384.data.data());

    PieceIndex idx;
    idx.file_size = out.size;
    if (out.size == 0) {
        idx.leaves = {EmptyFileRoot()};
        idx.pieces_root = EmptyFileRoot();
    } else {
        const size_t n = real_leaves.size();
        size_t width = 1;
        while (width < n) width <<= 1;
        idx.leaves = std::move(real_leaves);
        for (size_t i = n; i < width; ++i) idx.leaves.push_back(ChunkPad(i));
        const auto rows = BuildChunkTreeFromLeaves(idx.leaves);
        if (rows.empty()) {
            err = "chunk tree";
            return false;
        }
        idx.pieces_root = rows.back()[0];
    }
    out.pieces_root = idx.pieces_root;
    return store.SavePieceIndex(staging_artifact, file_index, idx, err);
}

ModelCatalog::ModelCatalog(fs::path dir, uint64_t quota_bytes)
    : m_dir(std::move(dir)), m_store(m_dir / "store", quota_bytes)
{
    m_policy.storage_quota_bytes = quota_bytes;
    m_policy.seed_mode = SeedMode::AUTO;
    m_policy.seed_upon_download = true;
    fs::create_directories(m_dir);
    std::string err;
    LoadLocked(err);
}

void ModelCatalog::DemandSeedLocked(CatalogEntry& e)
{
    if (!ShouldDemandSeed(m_policy, e.admission)) return;
    if (e.admission == AdmissionLevel::BYTES_VERIFIED ||
        e.admission == AdmissionLevel::STRUCTURE_VERIFIED ||
        e.admission == AdmissionLevel::PROFILE_VERIFIED ||
        e.admission == AdmissionLevel::RUNTIME_OBSERVED ||
        e.admission == AdmissionLevel::PINNED) {
        e.bytes_verified = true;
    }
    e.seeded = true;
    if (!e.seeding_started_at) e.seeding_started_at = GetTime();
    if (e.admission != AdmissionLevel::PINNED && e.admission != AdmissionLevel::ENCRYPTED_UNQUALIFIED) {
        e.admission = AdmissionLevel::SEEDING;
    }
}

void ModelCatalog::SetPolicy(PreservationPolicy p)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const uint64_t hard = m_store.QuotaBytes();
    if (p.storage_quota_bytes == 0 || p.storage_quota_bytes > hard) p.storage_quota_bytes = hard;
    m_policy = p;
}

PreservationPolicy ModelCatalog::Policy() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_policy;
}

bool ModelCatalog::ApplyDemandSeed(const Digest48& model_id, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& m : m_models) {
        if (m.model_id == model_id || m.artifact_id == model_id) {
            DemandSeedLocked(m);
            return PersistLocked(err);
        }
    }
    err = "unknown model";
    return false;
}

bool ModelCatalog::EnforceQuota(uint64_t need_bytes, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_store.EvictUnpinned();
    const uint64_t cap = m_policy.storage_quota_bytes ? std::min(m_policy.storage_quota_bytes, m_store.QuotaBytes()) : m_store.QuotaBytes();
    if (!cap) {
        err = "payload storage is 0 until -modelstorage / -modelcache allocates a quota";
        return false;
    }
    if (m_store.UsedBytes() + need_bytes <= cap) return true;
    const int64_t now = GetTime();
    std::vector<EvictItem> items;
    items.reserve(m_models.size());
    uint64_t pinned_bytes = 0;
    for (const auto& m : m_models) {
        EvictItem it;
        it.model_id = m.model_id;
        it.artifact_id = m.artifact_id;
        it.pinned = m.pinned;
        it.seeded = m.seeded;
        it.observed_sources = m.observed_sources;
        it.incomplete = m.incomplete || m.admission == AdmissionLevel::FETCHING;
        it.failed_unqualified = m.admission == AdmissionLevel::FAILED || m.admission == AdmissionLevel::ENCRYPTED_UNQUALIFIED;
        it.expired_ciphertext = m.admission == AdmissionLevel::ENCRYPTED_UNQUALIFIED;
        it.giveback_complete = GiveBackComplete(m_policy, m.useful_bytes_served, m.useful_bytes_received,
                                               m.seeding_started_at ? m.seeding_started_at : m.imported_at, now);
        const int64_t protect_from = m.completed_at ? m.completed_at : m.imported_at;
        it.recently_protected = !m.pinned && protect_from > 0 && (now - protect_from) < m_policy.retain_seconds &&
                               !it.giveback_complete;
        it.last_access_at = m.last_access_at ? m.last_access_at : m.imported_at;
        for (const auto& f : m.core.files) it.bytes += f.size;
        if (m.pinned) pinned_bytes += it.bytes;
        items.push_back(it);
    }
    std::sort(items.begin(), items.end(), [](const EvictItem& a, const EvictItem& b) {
        const int pa = EvictPriority(a);
        const int pb = EvictPriority(b);
        if (pa != pb) return pa < pb;
        if (a.last_access_at != b.last_access_at) return a.last_access_at < b.last_access_at;
        if (a.observed_sources != b.observed_sources) return a.observed_sources > b.observed_sources;
        return a.bytes > b.bytes;
    });
    for (const auto& it : items) {
        if (m_store.UsedBytes() + need_bytes <= cap) break;
        if (it.pinned) continue;
        if (m_active_artifacts.count(it.artifact_id)) continue;
        if (!m_store.RemoveArtifact(it.artifact_id, err)) return false;
        DropPieceTreeCache(it.artifact_id);
        m_models.erase(std::remove_if(m_models.begin(), m_models.end(), [&](const CatalogEntry& m) {
            return m.model_id == it.model_id;
        }), m_models.end());
    }
    if (m_store.UsedBytes() + need_bytes > cap) {
        if (pinned_bytes >= cap) {
            err = "PINNED_STORAGE_PRESSURE";
        } else {
            err = "disk quota";
        }
        return false;
    }
    return PersistLocked(err);
}

bool ModelCatalog::PersistLocked(std::string& err)
{
    UniValue arr(UniValue::VARR);
    for (const auto& m : m_models) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("model_id", m.model_id.Hex());
        o.pushKV("artifact_id", m.artifact_id.Hex());
        o.pushKV("label", m.label);
        o.pushKV("seeded", m.seeded);
        o.pushKV("pinned", m.pinned);
        o.pushKV("observed_sources", m.observed_sources);
        o.pushKV("admission", AdmissionLevelName(m.admission));
        o.pushKV("bytes_verified", m.bytes_verified);
        o.pushKV("source_path", m.source_path);
        o.pushKV("imported_at", m.imported_at);
        o.pushKV("completed_at", m.completed_at);
        o.pushKV("last_access_at", m.last_access_at);
        o.pushKV("last_served_at", m.last_served_at);
        o.pushKV("useful_bytes_served", m.useful_bytes_served);
        o.pushKV("useful_bytes_received", m.useful_bytes_received);
        o.pushKV("seeding_started_at", m.seeding_started_at);
        o.pushKV("incomplete", m.incomplete);
        o.pushKV("format_profile", m.core.format_profile);
        o.pushKV("execution_profile", m.core.execution_profile);
        o.pushKV("config_sha384", m.core.config_sha384.Hex());
        o.pushKV("tokenizer_sha384", m.core.tokenizer_sha384.Hex());
        UniValue files(UniValue::VARR);
        for (const auto& f : m.core.files) files.push_back(CoreFileJson(f));
        o.pushKV("files", files);
        arr.push_back(o);
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("models", arr);
    UniValue peers(UniValue::VARR);
    for (const auto& p : m_peers) peers.push_back(p);
    root.pushKV("peers", peers);
    const fs::path tmp = m_dir / "catalog.json.tmp";
    const fs::path final_path = m_dir / "catalog.json";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
        err = "catalog write failed";
        return false;
    }
    out << root.write(2, 0) << "\n";
    out.close();
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "catalog rename failed";
        return false;
    }
    return true;
}

bool ModelCatalog::LoadLocked(std::string& err)
{
    m_models.clear();
    const fs::path path = m_dir / "catalog.json";
    std::ifstream in(path);
    if (!in) return true;
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    if (!root.read(raw) || !root.isObject()) {
        err = "catalog json";
        return false;
    }
    if (root.exists("peers")) {
        for (const auto& p : root["peers"].getValues()) m_peers.push_back(p.get_str());
    }
    if (!root.exists("models")) return true;
    for (const auto& o : root["models"].getValues()) {
        CatalogEntry e;
        if (!Digest48::FromHex(o["model_id"].get_str(), e.model_id, err)) return false;
        if (!Digest48::FromHex(o["artifact_id"].get_str(), e.artifact_id, err)) return false;
        e.label = o["label"].get_str();
        e.seeded = o["seeded"].get_bool();
        e.pinned = o["pinned"].get_bool();
        if (o.exists("observed_sources")) e.observed_sources = o["observed_sources"].getInt<int>();
        e.source_path = o["source_path"].get_str();
        if (o.exists("imported_at")) e.imported_at = o["imported_at"].getInt<int64_t>();
        if (o.exists("completed_at")) e.completed_at = o["completed_at"].getInt<int64_t>();
        if (o.exists("last_access_at")) e.last_access_at = o["last_access_at"].getInt<int64_t>();
        if (o.exists("last_served_at")) e.last_served_at = o["last_served_at"].getInt<int64_t>();
        if (o.exists("useful_bytes_served")) e.useful_bytes_served = o["useful_bytes_served"].getInt<int64_t>();
        if (o.exists("useful_bytes_received")) e.useful_bytes_received = o["useful_bytes_received"].getInt<int64_t>();
        if (o.exists("seeding_started_at")) e.seeding_started_at = o["seeding_started_at"].getInt<int64_t>();
        if (o.exists("incomplete")) e.incomplete = o["incomplete"].get_bool();
        e.core.version = 2;
        e.core.format_profile = static_cast<uint16_t>(o["format_profile"].getInt<int>());
        e.core.execution_profile = static_cast<uint16_t>(o["execution_profile"].getInt<int>());
        if (!Digest48::FromHex(o["config_sha384"].get_str(), e.core.config_sha384, err)) return false;
        if (!Digest48::FromHex(o["tokenizer_sha384"].get_str(), e.core.tokenizer_sha384, err)) return false;
        for (const auto& f : o["files"].getValues()) {
            CoreFile cf;
            if (!CoreFileFromJson(f, cf, err)) return false;
            e.core.files.push_back(cf);
        }
        e.artifact.version = 2;
        e.artifact.codec = 1;
        e.artifact.model_id = e.model_id;
        e.artifact.files = e.core.files;
        e.admission = e.pinned ? AdmissionLevel::PINNED :
                      (e.seeded ? AdmissionLevel::SEEDING : AdmissionLevel::STRUCTURE_VERIFIED);
        if (o.exists("bytes_verified")) e.bytes_verified = o["bytes_verified"].get_bool();
        else e.bytes_verified = e.seeded || e.pinned || AdmissionImpliesBytesVerified(e.admission);
        if (e.pinned) {
            std::string pin_err;
            m_store.Pin(e.model_id, pin_err);
            m_store.Pin(e.artifact_id, pin_err);
        }
        m_models.push_back(std::move(e));
    }
    return true;
}

bool ModelCatalog::ImportPath(const std::string& path, bool pin, CatalogEntry& out, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_store.QuotaBytes() == 0) {
        err = "payload storage is 0 until -modelstorage / -modelcache allocates a quota";
        return false;
    }
    const fs::path src = fs::PathFromString(path);
    if (!fs::exists(src)) {
        err = "path does not exist";
        return false;
    }
    std::vector<std::pair<fs::path, std::string>> files;
    if (fs::is_regular_file(src)) {
        const std::string name = fs::PathToString(src.filename());
        std::string perr;
        if (!IsPortableRelPath(name, perr)) {
            err = perr;
            return false;
        }
        files.emplace_back(src, name);
    } else if (fs::is_directory(src)) {
        for (const auto& ent : fs::recursive_directory_iterator(src)) {
            if (!ent.is_regular_file()) continue;
            fs::path rel = fs::relative(ent.path(), src);
            std::string rels = rel.generic_string();
            std::string perr;
            if (!IsPortableRelPath(rels, perr)) continue;
            bool skip = false;
            (void)RoleFromRelPath(rels, skip);
            if (skip) continue;
            files.emplace_back(ent.path(), rels);
        }
    } else {
        err = "not a file or directory";
        return false;
    }
    if (files.empty()) {
        err = "no importable files (pickle/.pt/.py/.so/.bin skipped)";
        return false;
    }
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) { return a.second < b.second; });

    std::ostringstream nonce;
    nonce << std::hex << std::random_device{}() << std::random_device{}();
    const Digest48 staging = StagingId(nonce.str());

    std::vector<CoreFile> cores;
    bool saw_st = false, saw_gguf = false;
    QualReport last_qual;
    uint32_t file_index = 0;
    for (const auto& [p, rel] : files) {
        CoreFile cf;
        if (!ImportRegularFile(m_store, staging, file_index, p, rel, cf, &last_qual, err)) {
            return false;
        }
        if (ToLower(rel).ends_with(".safetensors")) saw_st = true;
        if (ToLower(rel).ends_with(".gguf")) saw_gguf = true;
        cores.push_back(cf);
        ++file_index;
    }

    ModelCore mc;
    mc.version = 2;
    mc.format_profile = saw_gguf && !saw_st ? 2 : 1;
    mc.execution_profile = 0;
    for (const auto& cf : cores) {
        if (cf.role == FileRole::CONFIG && mc.config_sha384.IsNull()) mc.config_sha384 = cf.sha384;
        if (cf.role == FileRole::TOKENIZER && mc.tokenizer_sha384.IsNull()) mc.tokenizer_sha384 = cf.sha384;
    }
    mc.files = cores;
    std::vector<unsigned char> encoded;
    if (!EncodeModelCore(mc, encoded, err)) return false;
    const Digest48 model_id = ModelCoreId(encoded);

    ArtifactCore ac;
    ac.version = 2;
    ac.codec = 1;
    ac.model_id = model_id;
    ac.files = cores;
    std::vector<unsigned char> aenc;
    if (!EncodeArtifactCore(ac, aenc, err)) return false;
    const Digest48 artifact_id = ArtifactCoreId(aenc);
    if (!m_store.RenameArtifact(staging, artifact_id, err)) return false;
    DropPieceTreeCache(staging);

    out = {};
    out.model_id = model_id;
    out.artifact_id = artifact_id;
    out.label = fs::PathToString(src.filename());
    out.seeded = false;
    out.pinned = pin;
    out.admission = pin ? AdmissionLevel::PINNED : AdmissionLevel::STRUCTURE_VERIFIED;
    out.bytes_verified = pin;
    out.core = std::move(mc);
    out.artifact = std::move(ac);
    out.source_path = path;
    out.imported_at = GetTime();
    out.completed_at = out.imported_at;
    out.last_access_at = out.imported_at;
    out.incomplete = false;
    if (pin) {
        std::string pin_err;
        m_store.Pin(model_id, pin_err);
        m_store.Pin(artifact_id, pin_err);
    }
    DemandSeedLocked(out);
    m_models.push_back(out);
    return PersistLocked(err);
}

bool ModelCatalog::Seed(const Digest48& model_id, bool on, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& m : m_models) {
        if (m.model_id == model_id) {
            if (on) {
                m.seeded = true;
                m.bytes_verified = m.bytes_verified || AdmissionImpliesBytesVerified(m.admission);
                m.admission = AdmissionLevel::SEEDING;
            } else {
                m.seeded = false;
            }
            return PersistLocked(err);
        }
    }
    err = "unknown model";
    return false;
}

bool ModelCatalog::PinModel(const Digest48& model_id, bool on, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& m : m_models) {
        if (m.model_id == model_id || m.artifact_id == model_id) {
            m.pinned = on;
            if (on) {
                m.admission = AdmissionLevel::PINNED;
                std::string pin_err;
                m_store.Pin(m.model_id, pin_err);
                m_store.Pin(m.artifact_id, pin_err);
            } else {
                m_store.Unpin(m.model_id);
                m_store.Unpin(m.artifact_id);
                if (m.seeded) m.admission = AdmissionLevel::SEEDING;
                else m.admission = AdmissionLevel::STRUCTURE_VERIFIED;
            }
            return PersistLocked(err);
        }
    }
    err = "unknown model";
    return false;
}

void ModelCatalog::SetQuotaBytes(uint64_t bytes)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_store.SetQuotaBytes(bytes);
    m_policy.storage_quota_bytes = bytes;
}

void ModelCatalog::BeginTransfer(const Digest48& artifact)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_active_artifacts.insert(artifact);
}

void ModelCatalog::EndTransfer(const Digest48& artifact)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_active_artifacts.erase(artifact);
}

UniValue ModelCatalog::FileAvailabilityJson(const Digest48& artifact, const ModelCore& core) const
{
    UniValue files(UniValue::VARR);
    uint32_t fi = 0;
    for (const auto& f : core.files) {
        UniValue one(UniValue::VOBJ);
        one.pushKV("file_index", static_cast<int>(fi));
        one.pushKV("file_size", f.size);
        std::vector<uint32_t> have;
        m_store.ListCommittedPieces(artifact, fi, have);
        std::string rerr;
        std::vector<PieceRange> ranges;
        CompactPieceRanges(have, ranges, rerr);
        one.pushKV("ranges", PieceRangesToJson(ranges));
        const uint32_t n = f.size == 0 ? 0u : static_cast<uint32_t>((f.size + PIECE_SIZE - 1) / PIECE_SIZE);
        const bool complete = PieceComplete(f.size, static_cast<uint32_t>(have.size())) && have.size() == n;
        one.pushKV("complete", complete);
        one.pushKV("piece_count", static_cast<int>(have.size()));
        one.pushKV("pieces_total", static_cast<int>(n));
        one.pushKV("piece_size", static_cast<int64_t>(PIECE_SIZE));
        one.pushKV("hash_alg", "sha384");
        files.push_back(one);
        ++fi;
    }
    return files;
}

uint64_t ModelCatalog::PinnedBytes() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    uint64_t n = 0;
    for (const auto& m : m_models) {
        if (!m.pinned) continue;
        for (const auto& f : m.core.files) n += f.size;
    }
    return n;
}

uint64_t ModelCatalog::ReclaimableBytes() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    uint64_t n = 0;
    for (const auto& m : m_models) {
        if (m.pinned) continue;
        for (const auto& f : m.core.files) n += f.size;
    }
    return n;
}

bool ModelCatalog::List(UniValue& out) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    out = UniValue(UniValue::VOBJ);
    out.pushKV("schema_version", 2);
    out.pushKV("coverage", "incomplete");
    out.pushKV("local_count", static_cast<int>(m_models.size()));
    UniValue arr(UniValue::VARR);
    for (const auto& m : m_models) {
        UniValue o(UniValue::VOBJ);
        std::string uri, e;
        EncodeResource(ResourceKind::MODEL, m.model_id, uri, e);
        o.pushKV("uri", uri);
        o.pushKV("model_id", m.model_id.Hex());
        o.pushKV("artifact_id", m.artifact_id.Hex());
        o.pushKV("label", m.label);
        o.pushKV("seeded", m.seeded);
        o.pushKV("pinned", m.pinned);
        o.pushKV("observed_sources", m.observed_sources);
        o.pushKV("admission", AdmissionLevelName(m.admission));
        o.pushKV("bytes_verified", m.bytes_verified || AdmissionImpliesBytesVerified(m.admission));
        o.pushKV("structure_verified", AdmissionImpliesStructureVerified(m.admission));
        if (m.bytes_verified || AdmissionImpliesBytesVerified(m.admission)) {
            o.pushKV("content_admission", "BYTES_VERIFIED");
        }
        uint64_t bytes = 0;
        for (const auto& f : m.core.files) bytes += f.size;
        o.pushKV("bytes", bytes);
        o.pushKV("incomplete", m.incomplete);
        UniValue files = FileAvailabilityJson(m.artifact_id, m.core);
        bool all_complete = !files.getValues().empty() || m.core.files.empty();
        for (const auto& f : files.getValues()) {
            if (!f["complete"].get_bool()) all_complete = false;
        }
        if (m.core.files.empty()) all_complete = !m.incomplete;
        o.pushKV("complete", all_complete && !m.incomplete);
        o.pushKV("files", files);
        arr.push_back(o);
    }
    out.pushKV("models", arr);
    return true;
}

bool ModelCatalog::GetManifest(const Digest48& id, UniValue& out, std::string& err) const
{
    CatalogEntry e;
    if (!Find(id, e)) {
        err = "unknown model or artifact";
        return false;
    }
    std::string model_uri, artifact_uri, e2;
    EncodeResource(ResourceKind::MODEL, e.model_id, model_uri, e2);
    EncodeResource(ResourceKind::ARTIFACT, e.artifact_id, artifact_uri, e2);
    out = UniValue(UniValue::VOBJ);
    out.pushKV("schema_version", 2);
    out.pushKV("model_uri", model_uri);
    out.pushKV("artifact_uri", artifact_uri);
    out.pushKV("model_id", e.model_id.Hex());
    out.pushKV("artifact_id", e.artifact_id.Hex());
    out.pushKV("format_profile", e.core.format_profile);
    out.pushKV("execution_profile", e.core.execution_profile);
    out.pushKV("execution_note", "0 means unqualified; granite MoE/Mamba is not dense-decoder-v1");
    UniValue files(UniValue::VARR);
    for (const auto& f : e.core.files) files.push_back(CoreFileJson(f));
    out.pushKV("files", files);
    out.pushKV("file_count", static_cast<int>(e.core.files.size()));
    out.pushKV("piece_size", static_cast<int64_t>(PIECE_SIZE));
    out.pushKV("hash_alg", "sha384");
    out.pushKV("seeded", e.seeded);
    out.pushKV("admission", AdmissionLevelName(e.admission));
    out.pushKV("bytes_verified", e.bytes_verified || AdmissionImpliesBytesVerified(e.admission));
    out.pushKV("structure_verified", AdmissionImpliesStructureVerified(e.admission));
    if (e.bytes_verified || AdmissionImpliesBytesVerified(e.admission)) {
        out.pushKV("content_admission", "BYTES_VERIFIED");
    }
    out.pushKV("qualification", "structure only; not usefulness, safety, or alignment");
    UniValue files_av = FileAvailabilityJson(e.artifact_id, e.core);
    bool all_complete = !e.incomplete;
    for (const auto& f : files_av.getValues()) {
        if (!f["complete"].get_bool()) all_complete = false;
    }
    out.pushKV("complete", all_complete && !e.incomplete);
    out.pushKV("incomplete", e.incomplete);
    return true;
}

bool ModelCatalog::Find(const Digest48& model_or_artifact, CatalogEntry& out) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (const auto& m : m_models) {
        if (m.model_id == model_or_artifact || m.artifact_id == model_or_artifact) {
            out = m;
            return true;
        }
    }
    return false;
}

bool ModelCatalog::FindExact(ResourceKind kind, const Digest48& digest, CatalogEntry& out) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (const auto& m : m_models) {
        if (kind == ResourceKind::MODEL && m.model_id == digest) {
            out = m;
            return true;
        }
        if (kind == ResourceKind::ARTIFACT && m.artifact_id == digest) {
            out = m;
            return true;
        }
    }
    return false;
}

bool ModelCatalog::MarkIncomplete(const Digest48& model_or_artifact, bool incomplete, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& m : m_models) {
        if (!(m.model_id == model_or_artifact || m.artifact_id == model_or_artifact)) continue;
        m.incomplete = incomplete;
        if (incomplete) {
            m.bytes_verified = false;
            m.admission = AdmissionLevel::FETCHING;
            m.completed_at = 0;
        }
        return PersistLocked(err);
    }
    err = "unknown model";
    return false;
}

bool ModelCatalog::NoteUsefulBytes(const Digest48& model_or_artifact, int64_t served_delta, int64_t received_delta, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& m : m_models) {
        if (!(m.model_id == model_or_artifact || m.artifact_id == model_or_artifact)) continue;
        const int64_t now = GetTime();
        if (served_delta > 0) {
            m.useful_bytes_served += served_delta;
            m.last_served_at = now;
        }
        if (received_delta > 0) {
            m.useful_bytes_received += received_delta;
            m.last_access_at = now;
        }
        return PersistLocked(err);
    }
    err = "unknown model";
    return false;
}

void ModelCatalog::DropPieceTreeCache(const Digest48& artifact) const
{
    std::lock_guard<std::mutex> lock(m_piece_tree_mu);
    auto it = m_piece_trees.lower_bound(PieceTreeKey{artifact, 0});
    while (it != m_piece_trees.end() && it->first.first == artifact) {
        it = m_piece_trees.erase(it);
    }
}

void ModelCatalog::DropPieceTreeCache(const Digest48& artifact, uint32_t file_index) const
{
    std::lock_guard<std::mutex> lock(m_piece_tree_mu);
    m_piece_trees.erase(PieceTreeKey{artifact, file_index});
}

bool ModelCatalog::GetVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                      std::vector<unsigned char>& bytes, std::vector<Digest48>& proof,
                                      uint64_t& file_size, std::string& err) const
{
    Digest48 pieces_root;
    std::vector<Digest48> cached_proof;
    bool have_tree = false;
    {
        std::lock_guard<std::mutex> lock(m_piece_tree_mu);
        const auto it = m_piece_trees.find(PieceTreeKey{artifact, file_index});
        if (it != m_piece_trees.end() && !it->second.rows.empty() &&
            piece_index < it->second.rows.front().size()) {
            pieces_root = it->second.pieces_root;
            file_size = it->second.file_size;
            cached_proof = PieceProof(it->second.rows, piece_index);
            have_tree = true;
        }
    }
    if (have_tree) {
        if (!m_store.GetPiece(artifact, file_index, piece_index, bytes, err)) return false;
        proof = std::move(cached_proof);
        if (VerifyPiece(pieces_root, file_size, piece_index, bytes, proof)) {
            return true;
        }
        DropPieceTreeCache(artifact, file_index);
        err.clear();
    }

    PieceIndex idx;
    std::string index_err;
    if (m_store.LoadPieceIndex(artifact, file_index, idx, index_err)) {
        file_size = idx.file_size;
        auto rows = BuildChunkTreeFromLeaves(idx.leaves);
        if (rows.empty()) {
            err = "chunk tree";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(m_piece_tree_mu);
            CachedPieceTree entry;
            entry.pieces_root = idx.pieces_root;
            entry.file_size = idx.file_size;
            entry.leaves = std::move(idx.leaves);
            entry.rows = rows;
            m_piece_trees[PieceTreeKey{artifact, file_index}] = std::move(entry);
        }
        if (!m_store.GetPiece(artifact, file_index, piece_index, bytes, err)) return false;
        proof = PieceProof(rows, piece_index);
        if (!VerifyPiece(idx.pieces_root, file_size, piece_index, bytes, proof)) {
            err = "local piece proof failed";
            DropPieceTreeCache(artifact, file_index);
            return false;
        }
        return true;
    }

    Digest48 proof_root;
    if (!m_store.LoadPieceProof(artifact, file_index, piece_index, file_size, proof_root, proof, err)) {
        if (err.empty()) err = index_err;
        return false;
    }
    if (!m_store.GetPiece(artifact, file_index, piece_index, bytes, err)) return false;
    if (!VerifyPiece(proof_root, file_size, piece_index, bytes, proof)) {
        err = "local piece proof failed";
        return false;
    }
    return true;
}

bool ModelCatalog::PutFetchedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                     Span<const unsigned char> bytes, const std::vector<Digest48>& proof,
                                     uint64_t file_size, const Digest48& pieces_root, std::string& err)
{
    if (!VerifyPiece(pieces_root, file_size, piece_index, bytes, proof)) {
        err = "corrupt chunk";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        bool found = false;
        for (const auto& m : m_models) {
            if (!(m.artifact_id == artifact)) continue;
            found = true;
            if (file_index >= m.core.files.size()) {
                err = "wrong file index";
                return false;
            }
            if (m.core.files[file_index].pieces_root != pieces_root) {
                err = "wrong file index";
                return false;
            }
            if (m.core.files[file_index].size != file_size) {
                err = "file size mismatch";
                return false;
            }
            break;
        }
        if (!found) {
            err = "unknown artifact";
            return false;
        }
    }
    const Digest48 leaf = ChunkLeaf(piece_index, bytes);
    if (!m_store.PutVerifiedPiece(artifact, file_index, piece_index, bytes, leaf, err)) return false;
    {
        std::string perr;
        (void)m_store.SavePieceProof(artifact, file_index, piece_index, file_size, pieces_root, proof, perr);
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (auto& m : m_models) {
            if (!(m.artifact_id == artifact)) continue;
            m.incomplete = true;
            if (ShouldDemandSeed(m_policy, m.admission) || m.seeded) {
                m.seeded = true;
                if (!m.seeding_started_at) m.seeding_started_at = GetTime();
            }
            m.last_access_at = GetTime();
            m.useful_bytes_received += static_cast<int64_t>(bytes.size());
            break;
        }
        PersistLocked(err);
    }
    {
        std::lock_guard<std::mutex> lock(m_piece_tree_mu);
        const auto it = m_piece_trees.find(PieceTreeKey{artifact, file_index});
        if (it != m_piece_trees.end() && it->second.pieces_root != pieces_root) {
            m_piece_trees.erase(it);
        }
    }
    return true;
}

void ModelCatalog::AddPeer(const std::string& endpoint)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (std::find(m_peers.begin(), m_peers.end(), endpoint) == m_peers.end()) {
        m_peers.push_back(endpoint);
        std::string err;
        PersistLocked(err);
    }
}

std::vector<std::string> ModelCatalog::Peers() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_peers;
}

bool ModelCatalog::VerifyFileDigest(const Digest48& artifact, uint32_t file_index, const Digest48& expected, std::string& err)
{
    PieceIndex idx;
    if (!m_store.LoadPieceIndex(artifact, file_index, idx, err)) return false;
    CSHA384 hasher;
    const uint64_t n = idx.file_size == 0 ? 0 : (idx.file_size + PIECE_SIZE - 1) / PIECE_SIZE;
    for (uint64_t i = 0; i < n; ++i) {
        std::vector<unsigned char> bytes;
        if (!m_store.GetPiece(artifact, file_index, static_cast<uint32_t>(i), bytes, err)) return false;
        if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    }
    Digest48 got;
    hasher.Finalize(got.data.data());
    if (got != expected) {
        err = "file sha384 mismatch";
        return false;
    }
    return true;
}

bool ModelCatalog::InstallFromManifest(const UniValue& manifest, std::string& err, bool complete)
{
    VerifiedManifest vm;
    if (!VerifyManifestAgainstRequest(manifest, vm, err)) return false;
    std::lock_guard<std::mutex> lock(m_mu);
    CatalogEntry e;
    e.model_id = vm.model_id;
    e.artifact_id = vm.artifact_id;
    e.label = "retrieved";
    e.core = std::move(vm.core);
    e.artifact = std::move(vm.artifact);
    if (complete) {
        e.admission = AdmissionLevel::BYTES_VERIFIED;
        e.bytes_verified = true;
        e.incomplete = false;
        e.completed_at = GetTime();
        DemandSeedLocked(e);
    } else {
        e.admission = AdmissionLevel::FETCHING;
        e.bytes_verified = false;
        e.incomplete = true;
        if (ShouldDemandSeed(m_policy, e.admission)) {
            e.seeded = true;
            if (!e.seeding_started_at) e.seeding_started_at = GetTime();
        }
    }
    for (auto& existing : m_models) {
        if (existing.model_id == e.model_id) {
            const bool pinned = existing.pinned;
            const int64_t imported = existing.imported_at;
            existing = e;
            existing.pinned = pinned;
            existing.imported_at = imported ? imported : GetTime();
            return PersistLocked(err);
        }
    }
    e.imported_at = GetTime();
    m_models.push_back(e);
    return PersistLocked(err);
}

} // namespace modelnet
