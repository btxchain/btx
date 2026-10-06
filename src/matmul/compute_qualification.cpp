// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/compute_qualification.h>

#include <matmul/compute_passport.h>
#include <matmul/compute_profile.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <crypto/sha384.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc.h>
#include <univalue.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/time.h>

#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>

#ifndef WIN32
#include <sys/file.h>
#endif

namespace pwc {
namespace {

constexpr size_t kMaxResponseBytes = 256 * 1024;

void PutU32(std::vector<unsigned char>& out, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    out.insert(out.end(), b, b + 4);
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char b[8];
    WriteLE64(b, v);
    out.insert(out.end(), b, b + 8);
}

bool Hex48(const std::string& hex, std::array<unsigned char, 48>& out)
{
    if (hex.size() != 96) return false;
    auto parsed = ParseHex(hex);
    if (parsed.size() != 48) return false;
    std::memcpy(out.data(), parsed.data(), 48);
    return true;
}

bool Hex32(const std::string& hex, std::array<unsigned char, 32>& out)
{
    if (hex.size() != 64) return false;
    auto parsed = ParseHex(hex);
    if (parsed.size() != 32) return false;
    std::memcpy(out.data(), parsed.data(), 32);
    return true;
}

/** The presented object must be the issued challenge. The id covers the anchor. */
bool PresentedChallengeMatchesId(const UniValue& challenge, std::string& err)
{
    if (!challenge.isObject() || !challenge.exists("network") || !challenge["network"].isStr() ||
        !challenge.exists("profile_name") || !challenge["profile_name"].isStr() ||
        !challenge.exists("challenge_id") || !challenge["challenge_id"].isStr() ||
        !challenge.exists("subject_digest") || !challenge["subject_digest"].isStr() ||
        !challenge.exists("issuer_nonce") || !challenge["issuer_nonce"].isStr() ||
        !challenge.exists("issued_at_ms") || !challenge["issued_at_ms"].isNum() ||
        !challenge.exists("expires_at_ms") || !challenge["expires_at_ms"].isNum() ||
        !challenge.exists("episode_count") || !challenge["episode_count"].isNum() ||
        !challenge.exists("anchor_height") || !challenge["anchor_height"].isNum() ||
        !challenge.exists("anchor_hash") || !challenge["anchor_hash"].isStr()) {
        err = "challenge id";
        return false;
    }
    QualificationFreshness in;
    in.network = challenge["network"].get_str();
    in.profile_name = challenge["profile_name"].get_str();
    if (!Hex32(challenge["subject_digest"].get_str(), in.subject) ||
        !Hex32(challenge["issuer_nonce"].get_str(), in.issuer_nonce)) {
        err = "challenge id";
        return false;
    }
    in.issued_at_ms = challenge["issued_at_ms"].getInt<int64_t>();
    in.expires_at_ms = challenge["expires_at_ms"].getInt<int64_t>();
    const int64_t episodes = challenge["episode_count"].getInt<int64_t>();
    if (episodes < 0 || episodes > static_cast<int64_t>(kQualEpisodeMax)) {
        err = "challenge id";
        return false;
    }
    in.episode_count = static_cast<uint32_t>(episodes);
    const int64_t height = challenge["anchor_height"].getInt<int64_t>();
    if (height < 0 || height > std::numeric_limits<int32_t>::max()) {
        err = "challenge id";
        return false;
    }
    in.anchor_height = static_cast<int32_t>(height);
    const auto anchor = uint256::FromHex(challenge["anchor_hash"].get_str());
    if (!anchor) {
        err = "challenge id";
        return false;
    }
    in.anchor_hash = *anchor;
    if (challenge.exists("max_elapsed_ms")) {
        if (!challenge["max_elapsed_ms"].isNum()) {
            err = "challenge id";
            return false;
        }
        in.max_elapsed_ms = challenge["max_elapsed_ms"].getInt<uint64_t>();
    }
    std::array<unsigned char, 48> got{};
    if (!Hex48(challenge["challenge_id"].get_str(), got) || got != ChallengeId(in)) {
        err = "challenge id";
        return false;
    }
    return true;
}

int64_t NowMs()
{
    return GetTime<std::chrono::milliseconds>().count();
}

class FileLock {
public:
    explicit FileLock(const fs::path& path)
    {
#ifndef WIN32
        m_fd = open(fs::PathToString(path).c_str(), O_RDWR | O_CREAT, 0600);
        if (m_fd >= 0) flock(m_fd, LOCK_EX);
#else
        (void)path;
#endif
    }
    ~FileLock()
    {
#ifndef WIN32
        if (m_fd >= 0) {
            flock(m_fd, LOCK_UN);
            close(m_fd);
        }
#endif
    }
    bool Ok() const
    {
#ifndef WIN32
        return m_fd >= 0;
#else
        return true;
#endif
    }
private:
#ifndef WIN32
    int m_fd{-1};
#endif
};

} // namespace

std::array<unsigned char, 48> ChallengeId(const QualificationFreshness& in)
{
    std::vector<unsigned char> buf;
    const std::string domain = "BTX_COMPUTE_QUAL_V1";
    buf.insert(buf.end(), domain.begin(), domain.end());
    buf.insert(buf.end(), in.network.begin(), in.network.end());
    buf.insert(buf.end(), in.profile_name.begin(), in.profile_name.end());
    buf.insert(buf.end(), in.subject.begin(), in.subject.end());
    buf.insert(buf.end(), in.issuer_nonce.begin(), in.issuer_nonce.end());
    PutU64(buf, static_cast<uint64_t>(in.issued_at_ms));
    PutU64(buf, static_cast<uint64_t>(in.expires_at_ms));
    PutU32(buf, in.episode_count);
    PutU32(buf, static_cast<uint32_t>(in.anchor_height));
    buf.insert(buf.end(), in.anchor_hash.begin(), in.anchor_hash.end());
    PutU32(buf, kHeaderConstructionVersion);
    PutU64(buf, in.max_elapsed_ms);
    std::array<unsigned char, 48> id{};
    CSHA384 hasher;
    hasher.Write(buf.data(), buf.size());
    hasher.Finalize(id.data());
    return id;
}

CBlockHeader EpisodeHeader(const std::array<unsigned char, 48>& challenge_id, uint32_t episode_index)
{
    auto tagged = [&](const char* label) {
        std::vector<unsigned char> buf;
        const std::string domain = "BTX_COMPUTE_P1E_V1";
        buf.insert(buf.end(), domain.begin(), domain.end());
        const std::string ep = "episode";
        buf.insert(buf.end(), ep.begin(), ep.end());
        buf.insert(buf.end(), challenge_id.begin(), challenge_id.end());
        PutU32(buf, episode_index);
        buf.insert(buf.end(), label, label + std::strlen(label));
        CSHA256 hasher;
        hasher.Write(buf.data(), buf.size());
        unsigned char out[32];
        hasher.Finalize(out);
        return uint256{Span<const unsigned char>{out, 32}};
    };
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce64 = episode_index;
    header.nNonce = episode_index;
    header.hashPrevBlock = tagged("prev");
    header.hashMerkleRoot = tagged("merkle");
    header.seed_a = tagged("seed_a");
    header.seed_b = tagged("seed_b");
    return header;
}

bool IssueQualification(const QualificationFreshness& in, bool allow_test, UniValue& challenge, std::string& err_code, std::string& err)
{
    if (in.episode_count < kQualEpisodeMin || in.episode_count > kQualEpisodeMax) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "episode_count out of range";
        return false;
    }
    if (in.expires_at_ms <= in.issued_at_ms) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "expiry";
        return false;
    }
    const WorkProfile* profile = FindWorkProfile(in.profile_name, allow_test, err_code);
    if (!profile) {
        err = err_code;
        return false;
    }
    QualificationFreshness bound = in;
    bound.profile_name = profile->profile_name;
    const auto id = ChallengeId(bound);
    UniValue o(UniValue::VOBJ);
    o.pushKV("kind", "btx_compute_qualification_v1");
    o.pushKV("schema_version", 1);
    o.pushKV("network", bound.network);
    o.pushKV("challenge_id", HexStr(id));
    o.pushKV("profile_id", ProfileIdHex(*profile));
    o.pushKV("profile_name", profile->profile_name);
    o.pushKV("test_only", profile->test_only);
    o.pushKV("subject_digest", HexStr(bound.subject));
    o.pushKV("issuer_nonce", HexStr(bound.issuer_nonce));
    o.pushKV("issued_at_ms", bound.issued_at_ms);
    o.pushKV("expires_at_ms", bound.expires_at_ms);
    o.pushKV("episode_count", static_cast<int64_t>(bound.episode_count));
    o.pushKV("anchor_height", bound.anchor_height);
    o.pushKV("anchor_hash", bound.anchor_hash.GetHex());
    o.pushKV("header_derivation_version", static_cast<int64_t>(kHeaderConstructionVersion));
    if (bound.max_elapsed_ms) o.pushKV("max_elapsed_ms", bound.max_elapsed_ms);
    challenge = std::move(o);
    return true;
}

bool SolveQualification(const UniValue& challenge, uint64_t time_budget_ms, bool allow_production,
                        UniValue& response, std::string& err_code, std::string& err,
                        const std::string& backend)
{
    if (!challenge.isObject() || !challenge.exists("profile_name") || !challenge["profile_name"].isStr() ||
        !challenge.exists("challenge_id") || !challenge["challenge_id"].isStr() ||
        !challenge.exists("episode_count") || !challenge["episode_count"].isNum()) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "challenge";
        return false;
    }
    std::string code;
    const WorkProfile* profile = FindWorkProfile(challenge["profile_name"].get_str(), /*allow_test=*/true, code);
    if (!profile || ProfileIdHex(*profile) != challenge["profile_id"].get_str()) {
        err_code = "COMPUTE_PROFILE_MISMATCH";
        err = "profile";
        return false;
    }
    if (!profile->test_only && !allow_production) {
        err_code = "COMPUTE_TIME_BUDGET_EXCEEDED";
        err = "production profile execution requires -enablecomputeproductionwork=1";
        return false;
    }
    const uint32_t n = static_cast<uint32_t>(challenge["episode_count"].getInt<int64_t>());
    if (n < kQualEpisodeMin || n > kQualEpisodeMax) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "episode_count";
        return false;
    }
    std::array<unsigned char, 48> cid{};
    if (!Hex48(challenge["challenge_id"].get_str(), cid)) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "challenge_id";
        return false;
    }
    std::string resolved_backend = "cpu";
    matmul::v4::rc::RCExactReplayAcceleration accel;
    bool use_device = false;
    if (!backend.empty() && backend != "cpu") {
        if (backend != "auto" && backend != "cuda" && backend != "hip" && backend != "metal" && backend != "ascend") {
            err_code = "COMPUTE_BACKEND_UNAVAILABLE";
            err = "backend";
            return false;
        }
        const auto resolved = matmul_v4::accel::ResolveExactGemmBackendForRC();
        const bool provider_ok = backend == "auto" || resolved.provider == backend;
        if (!resolved.self_qualified || resolved.backend.gemm_s8s8 == nullptr || !provider_ok) {
            err_code = "COMPUTE_BACKEND_UNAVAILABLE";
            err = resolved.reason.empty() ? "self-qualification" : resolved.reason;
            return false;
        }
        accel.gemm = resolved.backend;
        accel.backend = resolved.provider;
        accel.require_device = true;
        use_device = true;
        resolved_backend = resolved.provider;
    }
    const auto started = std::chrono::steady_clock::now();
    UniValue episodes(UniValue::VARR);
    uint64_t wall_us = 0;
    for (uint32_t i = 0; i < n; ++i) {
        if (time_budget_ms > 0) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
            if (static_cast<uint64_t>(elapsed) > time_budget_ms) {
                err_code = "COMPUTE_TIME_BUDGET_EXCEEDED";
                err = "time budget";
                return false;
            }
        }
        const CBlockHeader header = EpisodeHeader(cid, i);
        const auto t0 = std::chrono::steady_clock::now();
        const uint256 digest = use_device
            ? matmul::v4::rc::RecomputeResidentCurriculumAccelerated(
                  header, profile->params, /*height=*/0, {}, nullptr, nullptr, accel)
            : matmul::v4::rc::RecomputeResidentCurriculumReference(header, profile->params, /*height=*/0);
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
        if (digest.IsNull()) {
            err_code = use_device ? "COMPUTE_BACKEND_UNAVAILABLE" : "COMPUTE_DIGEST_MISMATCH";
            err = "null digest";
            return false;
        }
        wall_us += static_cast<uint64_t>(std::max<int64_t>(us, 0));
        UniValue ep(UniValue::VOBJ);
        ep.pushKV("index", static_cast<int64_t>(i));
        ep.pushKV("exact_replay_digest", digest.GetHex());
        ep.pushKV("advisory_wall_us", static_cast<uint64_t>(std::max<int64_t>(us, 0)));
        episodes.push_back(ep);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("kind", "btx_compute_qualification_response_v1");
    o.pushKV("schema_version", 1);
    o.pushKV("challenge_id", challenge["challenge_id"].get_str());
    o.pushKV("profile_id", ProfileIdHex(*profile));
    o.pushKV("subject_digest", challenge.exists("subject_digest") ? challenge["subject_digest"].get_str() : "");
    o.pushKV("episode_count", static_cast<int64_t>(n));
    o.pushKV("episodes", episodes);
    UniValue advisory(UniValue::VOBJ);
    advisory.pushKV("untrusted", true);
    advisory.pushKV("backend_requested", backend.empty() ? "cpu" : backend);
    advisory.pushKV("backend", resolved_backend);
    advisory.pushKV("backend_resolved", resolved_backend);
    advisory.pushKV("issuer_uses_cpu_reference", true);
    advisory.pushKV("total_wall_us", wall_us);
    o.pushKV("solver_telemetry", advisory);
    if (o.write().size() > kMaxResponseBytes) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "response too large";
        return false;
    }
    response = std::move(o);
    return true;
}

bool QualificationRegistry::Open(const fs::path& path, std::string& err)
{
    m_path = path;
    m_healthy = false;
    m_error.clear();
    m_quarantine.clear();
    m_entries.clear();
    if (!Load(err)) {
        m_healthy = false;
        m_error = err;
        return false;
    }
    m_healthy = true;
    return true;
}

UniValue QualificationRegistry::Health() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("healthy", m_healthy);
    o.pushKV("path", fs::PathToString(m_path));
    o.pushKV("entries", static_cast<uint64_t>(m_entries.size()));
    if (!m_quarantine.empty()) o.pushKV("quarantine_path", fs::PathToString(m_quarantine));
    if (!m_error.empty()) o.pushKV("error", m_error);
    return o;
}

bool QualificationRegistry::Load(std::string& err)
{
    if (!fs::exists(m_path)) {
        m_entries.clear();
        return true;
    }
    std::ifstream in(m_path);
    if (!in) {
        err = "registry unreadable";
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue parsed;
    if (!parsed.read(raw) || !parsed.isObject() || !parsed.exists("entries") || !parsed["entries"].isArray() ||
        !parsed.exists("schema") || !parsed["schema"].isNum() || parsed["schema"].getInt<int>() != 1) {
        m_quarantine = fs::PathFromString(fs::PathToString(m_path) + ".quarantine");
        std::error_code ec;
        fs::rename(m_path, m_quarantine, ec);
        err = "registry quarantined";
        return false;
    }
    m_entries.clear();
    for (const auto& row : parsed["entries"].getValues()) {
        if (!row.isObject()) {
            err = "registry quarantined";
            return false;
        }
        Entry e;
        e.id = row["id"].get_str();
        e.profile_id = row["profile_id"].get_str();
        e.subject = row["subject"].get_str();
        e.issued_at_ms = row["issued_at_ms"].getInt<int64_t>();
        e.expires_at_ms = row["expires_at_ms"].getInt<int64_t>();
        e.episode_count = static_cast<uint32_t>(row["episode_count"].getInt<int64_t>());
        e.max_elapsed_ms = row.exists("max_elapsed_ms") ? row["max_elapsed_ms"].getInt<uint64_t>() : 0;
        e.redeemed = row["redeemed"].get_bool();
        e.redeemed_at_ms = row.exists("redeemed_at_ms") ? row["redeemed_at_ms"].getInt<int64_t>() : 0;
        e.canonical = row.exists("canonical") ? row["canonical"].get_str() : "";
        m_entries.push_back(std::move(e));
    }
    return true;
}

bool QualificationRegistry::Save(std::string& err)
{
    UniValue entries(UniValue::VARR);
    for (const auto& e : m_entries) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("id", e.id);
        row.pushKV("profile_id", e.profile_id);
        row.pushKV("subject", e.subject);
        row.pushKV("issued_at_ms", e.issued_at_ms);
        row.pushKV("expires_at_ms", e.expires_at_ms);
        row.pushKV("episode_count", static_cast<int64_t>(e.episode_count));
        row.pushKV("max_elapsed_ms", e.max_elapsed_ms);
        row.pushKV("redeemed", e.redeemed);
        row.pushKV("redeemed_at_ms", e.redeemed_at_ms);
        row.pushKV("canonical", e.canonical);
        entries.push_back(row);
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("schema", 1);
    root.pushKV("entries", entries);
    fs::create_directories(m_path.parent_path());
    const fs::path tmp = m_path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "registry write";
            return false;
        }
        out << root.write() << "\n";
        out.flush();
        if (!out) {
            err = "registry write";
            return false;
        }
    }
    if (!RenameOver(tmp, m_path)) {
        err = "registry rename";
        return false;
    }
    return true;
}

QualificationRegistry::Entry* QualificationRegistry::Find(const std::string& id)
{
    for (auto& e : m_entries) {
        if (e.id == id) return &e;
    }
    return nullptr;
}

bool QualificationRegistry::RememberIssued(const UniValue& challenge, std::string& err_code, std::string& err)
{
    if (!m_healthy) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = m_error.empty() ? "registry unhealthy" : m_error;
        return false;
    }
    FileLock lock(fs::PathFromString(fs::PathToString(m_path) + ".lock"));
    if (!lock.Ok()) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "registry lock";
        return false;
    }
    if (!Load(err)) {
        m_healthy = false;
        m_error = err;
        err_code = "COMPUTE_CHALLENGE_INVALID";
        return false;
    }
    const std::string id = challenge["challenge_id"].get_str();
    if (Find(id)) return true;
    const int64_t now = NowMs();
    m_entries.erase(std::remove_if(m_entries.begin(), m_entries.end(), [&](const Entry& e) {
                        return !e.redeemed && e.expires_at_ms < now;
                    }),
                    m_entries.end());
    if (m_entries.size() >= kQualRegistryMax) {
        // Redeemed entries were never dropped, so the registry filled for good
        // after kQualRegistryMax redemptions. Dropping the oldest redeemed and
        // expired entries is safe: Verify() refuses an id it does not know, so a
        // dropped challenge reads "unknown" and can never be redeemed again.
        std::vector<size_t> evictable;
        for (size_t i = 0; i < m_entries.size(); ++i) {
            if (m_entries[i].redeemed && m_entries[i].expires_at_ms < now) evictable.push_back(i);
        }
        std::sort(evictable.begin(), evictable.end(), [&](size_t l, size_t r) {
            return m_entries[l].redeemed_at_ms < m_entries[r].redeemed_at_ms;
        });
        const size_t need = m_entries.size() - kQualRegistryMax + 1;
        if (evictable.size() >= need) {
            std::set<size_t> drop(evictable.begin(), evictable.begin() + need);
            std::vector<Entry> kept;
            kept.reserve(m_entries.size() - need);
            for (size_t i = 0; i < m_entries.size(); ++i) {
                if (!drop.count(i)) kept.push_back(std::move(m_entries[i]));
            }
            m_entries = std::move(kept);
        }
    }
    if (m_entries.size() >= kQualRegistryMax) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "registry full";
        return false;
    }
    Entry e;
    e.id = id;
    e.profile_id = challenge["profile_id"].get_str();
    e.subject = challenge["subject_digest"].get_str();
    e.issued_at_ms = challenge["issued_at_ms"].getInt<int64_t>();
    e.expires_at_ms = challenge["expires_at_ms"].getInt<int64_t>();
    e.episode_count = static_cast<uint32_t>(challenge["episode_count"].getInt<int64_t>());
    e.max_elapsed_ms = challenge.exists("max_elapsed_ms") ? challenge["max_elapsed_ms"].getInt<uint64_t>() : 0;
    e.canonical = challenge.write();
    m_entries.push_back(std::move(e));
    if (!Save(err)) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        return false;
    }
    return true;
}

bool QualificationRegistry::Verify(const UniValue& challenge, const UniValue& response, bool redeem, int64_t now_ms,
                                   UniValue& out, std::string& err_code, std::string& err)
{
    if (!m_healthy) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = m_error.empty() ? "registry unhealthy" : m_error;
        return false;
    }
    if (response.write().size() > kMaxResponseBytes) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "response too large";
        return false;
    }
    FileLock lock(fs::PathFromString(fs::PathToString(m_path) + ".lock"));
    if (!lock.Ok()) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "registry lock";
        return false;
    }
    if (!Load(err)) {
        m_healthy = false;
        m_error = err;
        err_code = "COMPUTE_CHALLENGE_INVALID";
        return false;
    }
    if (!challenge.isObject() || !response.isObject()) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "object";
        return false;
    }
    if (!PresentedChallengeMatchesId(challenge, err)) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        return false;
    }
    const std::string id = challenge["challenge_id"].get_str();
    if (response["challenge_id"].get_str() != id) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "challenge id";
        return false;
    }
    Entry* entry = Find(id);
    if (!entry) {
        err_code = "COMPUTE_CHALLENGE_UNKNOWN";
        err = "unknown";
        return false;
    }
    if (challenge["profile_id"].get_str() != entry->profile_id ||
        challenge["subject_digest"].get_str() != entry->subject ||
        challenge["issued_at_ms"].getInt<int64_t>() != entry->issued_at_ms ||
        challenge["expires_at_ms"].getInt<int64_t>() != entry->expires_at_ms ||
        static_cast<uint32_t>(challenge["episode_count"].getInt<int64_t>()) != entry->episode_count) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "challenge bytes";
        return false;
    }
    if (entry->redeemed) {
        err_code = "COMPUTE_CHALLENGE_REDEEMED";
        err = "redeemed";
        return false;
    }
    if (now_ms > entry->expires_at_ms) {
        err_code = "COMPUTE_CHALLENGE_EXPIRED";
        err = "expired";
        return false;
    }
    if (response["subject_digest"].get_str() != entry->subject) {
        err_code = "COMPUTE_SUBJECT_MISMATCH";
        err = "subject";
        return false;
    }
    if (response["profile_id"].get_str() != entry->profile_id) {
        err_code = "COMPUTE_PROFILE_MISMATCH";
        err = "profile";
        return false;
    }
    std::string code;
    const WorkProfile* profile = FindWorkProfile(entry->profile_id, /*allow_test=*/true, code);
    if (!profile) {
        err_code = "COMPUTE_PROFILE_MISMATCH";
        err = "profile";
        return false;
    }
    const auto episodes = response["episodes"];
    if (!episodes.isArray() || episodes.size() != entry->episode_count) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "episode count";
        return false;
    }
    std::set<int64_t> seen;
    std::array<unsigned char, 48> cid{};
    if (!Hex48(id, cid)) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "id";
        return false;
    }
    for (size_t i = 0; i < episodes.size(); ++i) {
        const UniValue& ep = episodes[i];
        if (!ep.isObject() || !ep.exists("index") || !ep.exists("exact_replay_digest")) {
            err_code = "COMPUTE_CHALLENGE_INVALID";
            err = "episode";
            return false;
        }
        const int64_t index = ep["index"].getInt<int64_t>();
        if (index < 0 || static_cast<uint32_t>(index) >= entry->episode_count || !seen.insert(index).second) {
            err_code = "COMPUTE_CHALLENGE_INVALID";
            err = "episode index";
            return false;
        }
        const auto claimed = uint256::FromHex(ep["exact_replay_digest"].get_str());
        if (!claimed) {
            err_code = "COMPUTE_DIGEST_MISMATCH";
            err = "digest";
            return false;
        }
        const uint256 actual = matmul::v4::rc::RecomputeResidentCurriculumReference(
            EpisodeHeader(cid, static_cast<uint32_t>(index)), profile->params, 0);
        if (*claimed != actual || actual.IsNull()) {
            err_code = "COMPUTE_DIGEST_MISMATCH";
            err = "digest";
            return false;
        }
    }
    const int64_t observed = now_ms - entry->issued_at_ms;
    if (observed < 0) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "clock";
        return false;
    }
    if (entry->max_elapsed_ms && static_cast<uint64_t>(observed) > entry->max_elapsed_ms) {
        err_code = "COMPUTE_RATE_TOO_LOW";
        err = "max elapsed";
        return false;
    }
    uint64_t rate = 0;
    const uint64_t demonstrated = static_cast<uint64_t>(entry->episode_count) * profile->microunits_per_episode;
    std::string rate_err;
    if (observed == 0 || !MicrounitsPerHour(entry->episode_count, static_cast<uint64_t>(observed) * 1000ull, rate, rate_err)) {
        rate = 0;
    }
    if (redeem) {
        entry->redeemed = true;
        entry->redeemed_at_ms = now_ms;
        if (!Save(err)) {
            err_code = "COMPUTE_CHALLENGE_INVALID";
            return false;
        }
    }
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("valid", true);
    summary.pushKV("challenge_id", id);
    summary.pushKV("profile_id", entry->profile_id);
    summary.pushKV("profile_name", profile->profile_name);
    summary.pushKV("test_only", profile->test_only);
    summary.pushKV("episode_count", static_cast<int64_t>(entry->episode_count));
    summary.pushKV("demonstrated_p1e_microunits", demonstrated);
    summary.pushKV("issuer_observed_elapsed_ms", observed);
    summary.pushKV("conservative_rate_p1e_microunits_per_hour", rate);
    summary.pushKV("redeemed", redeem || entry->redeemed);
    summary.pushKV("verified_at_ms", now_ms);
    summary.pushKV("client_timing_authoritative", false);
    out = std::move(summary);
    return true;
}

bool QualificationRegistry::Status(const std::string& challenge_id, int64_t now_ms, UniValue& out, std::string& err_code, std::string& err)
{
    if (!m_healthy) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = m_error;
        return false;
    }
    FileLock lock(fs::PathFromString(fs::PathToString(m_path) + ".lock"));
    if (!lock.Ok()) {
        err_code = "COMPUTE_CHALLENGE_INVALID";
        err = "registry lock";
        return false;
    }
    if (!Load(err)) {
        m_healthy = false;
        err_code = "COMPUTE_CHALLENGE_INVALID";
        return false;
    }
    UniValue o = Health();
    const Entry* entry = Find(challenge_id);
    if (!entry) {
        o.pushKV("status", "unknown");
        o.pushKV("challenge_id", challenge_id);
        out = std::move(o);
        return true;
    }
    std::string status = "issued";
    if (entry->redeemed) status = "redeemed";
    else if (now_ms > entry->expires_at_ms) status = "expired";
    o.pushKV("status", status);
    o.pushKV("challenge_id", entry->id);
    o.pushKV("profile_id", entry->profile_id);
    o.pushKV("subject_digest", entry->subject);
    o.pushKV("episode_count", static_cast<int64_t>(entry->episode_count));
    o.pushKV("issued_at_ms", entry->issued_at_ms);
    o.pushKV("redeemed_at_ms", entry->redeemed_at_ms);
    o.pushKV("redeemed", entry->redeemed);
    uint64_t rate = 0;
    if (entry->redeemed && entry->redeemed_at_ms > entry->issued_at_ms) {
        std::string code;
        const WorkProfile* profile = FindWorkProfile(entry->profile_id, /*allow_test=*/true, code);
        std::string rate_err;
        const uint64_t elapsed_us = static_cast<uint64_t>(entry->redeemed_at_ms - entry->issued_at_ms) * 1000ull;
        if (!profile || !MicrounitsPerHour(entry->episode_count, elapsed_us, rate, rate_err)) rate = 0;
    }
    o.pushKV("conservative_rate_p1e_microunits_per_hour", rate);
    out = std::move(o);
    return true;
}

} // namespace pwc
