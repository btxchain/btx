// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/import_coordinator.h>

#include <modelnet/import_plan.h>
#include <modelnet/io_executor.h>
#include <modelnet/provenance.h>
#include <modelnet/qualification.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_local.h>
#include <modelnet/source_registry.h>
#include <modelnet/source_torrent.h>
#include <modelnet/store.h>
#include <modelnet/types.h>
#include <random.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <set>

namespace modelnet {
namespace {

const char* KindName(ImportSourceKind k)
{
    return ImportSourceKindName(k);
}

const char* PhaseName(ImportPhase p)
{
    switch (p) {
    case ImportPhase::UNPREPARED: return "UNPREPARED";
    case ImportPhase::STAGING: return "STAGING";
    case ImportPhase::PUBLISH_READY: return "PUBLISH_READY";
    case ImportPhase::FAILED: return "FAILED";
    }
    return "UNPREPARED";
}

std::string ProvenanceFor(const ImportPlan& plan)
{
    if (plan.kind == ImportSourceKind::TORRENT || plan.kind == ImportSourceKind::MAGNET) {
        return TORRENT_PROVENANCE_NOTE;
    }
    if (plan.kind == ImportSourceKind::HUGGINGFACE) {
        return HUGGINGFACE_PROVENANCE_NOTE;
    }
    if (ImportKindIsRegistry(plan.kind) || plan.origins.size() > 1) {
        return REGISTRY_PROVENANCE_NOTE;
    }
    if (!plan.provenance_note.empty()) return plan.provenance_note;
    return "source_integrity_only;not_publisher_authorship";
}

std::string GenerateStagingUuid()
{
    unsigned char b[16];
    GetStrongRandBytes(Span<unsigned char>{b, sizeof(b)});
    b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
    b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
    static const char* hex = "0123456789abcdef";
    std::string out(36, '-');
    auto put = [&](int bi, int oi) {
        out[static_cast<size_t>(oi)] = hex[b[bi] >> 4];
        out[static_cast<size_t>(oi) + 1] = hex[b[bi] & 0xf];
    };
    put(0, 0);
    put(1, 2);
    put(2, 4);
    put(3, 6);
    put(4, 9);
    put(5, 11);
    put(6, 14);
    put(7, 16);
    put(8, 19);
    put(9, 21);
    put(10, 24);
    put(11, 26);
    put(12, 28);
    put(13, 30);
    put(14, 32);
    put(15, 34);
    return out;
}

std::vector<TorrentFileMap> TorrentMapFromPlan(const ImportPlan& plan)
{
    std::vector<TorrentFileMap> files;
    files.reserve(plan.files.size());
    for (const auto& f : plan.files) {
        TorrentFileMap m;
        m.name = f.source_path.empty() ? f.destination_path : f.source_path;
        m.size = f.size_bytes;
        m.padding = false;
        files.push_back(std::move(m));
    }
    return files;
}

} // namespace

bool ImportRelPathUnsafe(const std::string& rel)
{
    if (rel.empty()) return true;
    const std::string lower = ToLower(rel);
    if (lower.starts_with(".") || lower.find("/.") != std::string::npos) return true;
    if (LooksLikeExecutable(rel, Span<const unsigned char>{})) return true;
    return lower.ends_with(".bin") || lower.ends_with(".pickle") || lower.ends_with(".exe") ||
           lower.ends_with(".sig");
}

ImportCoordinator::ImportCoordinator(ImportPlan plan, fs::path stage_root)
    : m_plan(std::move(plan)), m_stage_root(std::move(stage_root)), m_staging_uuid(GenerateStagingUuid())
{
}

fs::path ImportCoordinator::StagingDir() const
{
    return m_stage_root / fs::PathFromString(m_staging_uuid);
}

bool ImportCoordinator::PrepareStaging(std::string& err)
{
    m_accepted.clear();
    m_verified.reset();
    m_fail_reason.clear();
    m_piece_origins.clear();
    m_bound_piece_origins.clear();
    m_origins_mixed_without_identity = false;
    for (const auto& f : m_plan.files) {
        const std::string dest = f.destination_path.empty() ? f.source_path : f.destination_path;
        std::string perr;
        if (dest.empty() || !IsPortableRelPath(dest, perr) || ImportRelPathUnsafe(dest) ||
            ImportRelPathUnsafe(f.source_path)) {
            continue;
        }
        ImportFileSpec keep = f;
        keep.destination_path = dest;
        m_accepted.push_back(std::move(keep));
    }
    if (m_accepted.empty()) {
        err = "no importable files (pickle/.pt/.py/.so/.bin skipped)";
        m_phase = ImportPhase::FAILED;
        m_fail_reason = err;
        return false;
    }
    fs::create_directories(StagingDir());
    if (!fs::exists(StagingDir()) || !fs::is_directory(StagingDir())) {
        err = "staging dir";
        m_phase = ImportPhase::FAILED;
        m_fail_reason = err;
        return false;
    }
    m_phase = ImportPhase::STAGING;
    const fs::path marker = StagingDir() / fs::PathFromString("staging.json");
    std::ofstream out(marker);
    if (!out) {
        err = "staging marker";
        m_phase = ImportPhase::FAILED;
        m_fail_reason = err;
        return false;
    }
    out << StatusJson().write();
    if (!out) {
        err = "staging marker";
        m_phase = ImportPhase::FAILED;
        m_fail_reason = err;
        return false;
    }
    return true;
}

bool ImportCoordinator::StageFromSource(ByteSource& src, const ImportFileSpec& spec, uint64_t budget_bytes,
                                        std::string& err)
{
    if (m_phase != ImportPhase::STAGING) {
        err = "not staging";
        return false;
    }
    const std::string dest = spec.destination_path.empty() ? spec.source_path : spec.destination_path;
    std::string perr;
    if (dest.empty() || !IsPortableRelPath(dest, perr) || ImportRelPathUnsafe(dest)) {
        err = perr.empty() ? "unsafe path" : perr;
        return false;
    }
    if (spec.size_bytes == 0) {
        err = "size";
        return false;
    }
    src.SelectFile(spec.source_path.empty() ? dest : spec.source_path, spec.sha384_hex);
    src.BindFileIdentity(spec.size_bytes, spec.piece_sha384_hex);
    const fs::path outp = StagingDir() / fs::PathFromString(dest);
    fs::create_directories(outp.parent_path());
    std::ofstream out(outp, std::ios::binary);
    if (!out) {
        err = "open";
        return false;
    }
    uint64_t remaining_budget = budget_bytes;
    uint64_t off = 0;
    IoExecutor io(1);
    if (!io.Submit(err)) return false;
    while (off < spec.size_bytes) {
        const uint64_t n = std::min<uint64_t>(PIECE_SIZE, spec.size_bytes - off);
        std::vector<unsigned char> bytes;
        const bool got = src.Read({off, n}, bytes, remaining_budget, err);
        if (!got) {
            io.Complete();
            return false;
        }
        if (bytes.size() != n) {
            io.Complete();
            err = "short read";
            return false;
        }
        if (off == 0 && (LooksLikePickle(bytes) || LooksLikeExecutable(dest, bytes))) {
            io.Complete();
            err = "pickle/.pt execution forbidden";
            return false;
        }
        if (!bytes.empty()) {
            out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        }
        if (!out) {
            io.Complete();
            err = "write";
            return false;
        }
        if (remaining_budget < n) {
            io.Complete();
            err = "credit exhausted";
            return false;
        }
        remaining_budget -= n;
        off += n;
    }
    io.Complete();
    out.close();
    if (!spec.sha384_hex.empty()) {
        Digest48 sha, root;
        uint64_t sz = 0;
        if (!HashFileSha384AndPiecesRoot(outp, sha, root, sz, err)) return false;
        if (sz != spec.size_bytes || sha.Hex() != spec.sha384_hex) {
            err = "HASH_MISMATCH";
            return false;
        }
    }
    const auto pieces = src.PieceOrigins();
    if (!pieces.empty()) {
        m_piece_origins.insert(m_piece_origins.end(), pieces.begin(), pieces.end());
    } else {
        const std::string fallback =
            !m_plan.origins.empty() ? m_plan.origins.front().type : ImportOriginTypeName(m_plan.kind);
        m_piece_origins.push_back(fallback);
    }
    const auto bound = src.BoundPieceOrigins();
    m_bound_piece_origins.insert(m_bound_piece_origins.end(), bound.begin(), bound.end());
    if (src.OriginsMixedWithoutIdentity()) m_origins_mixed_without_identity = true;
    if (!spec.sha384_hex.empty() && bound.empty() && !pieces.empty() && !m_origins_mixed_without_identity) {
        std::set<std::string> unique(pieces.begin(), pieces.end());
        if (unique.size() == 1) m_bound_piece_origins.push_back(*unique.begin());
    }
    return true;
}

bool ImportCoordinator::AcceptVerifiedManifest(const VerifiedManifest& vm, std::string& err)
{
    if (m_phase != ImportPhase::STAGING) {
        err = "not staging";
        return false;
    }
    if (vm.model_id.IsNull() || vm.artifact_id.IsNull()) {
        err = "verified manifest ids";
        return false;
    }
    if (!m_plan.expected_btx_manifest.empty() && m_plan.expected_btx_manifest != vm.model_id.Hex()) {
        err = "ID_MISMATCH";
        return false;
    }
    for (const auto& spec : m_plan.files) {
        if (spec.sha384_hex.empty()) continue;
        const std::string dest = spec.destination_path.empty() ? spec.source_path : spec.destination_path;
        for (const auto& cf : vm.core.files) {
            if (cf.path == dest && cf.sha384.Hex() != spec.sha384_hex) {
                err = "HASH_MISMATCH";
                return false;
            }
        }
    }
    if (!BindVerifiedManifestToStaged(vm, StagingDir(), err)) {
        return false;
    }
    m_verified = vm;
    m_phase = ImportPhase::PUBLISH_READY;
    const fs::path marker = StagingDir() / fs::PathFromString("staging.json");
    std::ofstream out(marker);
    if (out) out << StatusJson().write();
    return true;
}

Digest48 ImportCoordinator::FinalModelId() const
{
    if (!m_verified) return {};
    return m_verified->model_id;
}

Digest48 ImportCoordinator::FinalArtifactId() const
{
    if (!m_verified) return {};
    return m_verified->artifact_id;
}

UniValue ImportCoordinator::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("plan_id", m_plan.plan_id);
    o.pushKV("kind", KindName(m_plan.kind));
    o.pushKV("staging_uuid", m_staging_uuid);
    o.pushKV("phase", PhaseName(m_phase));
    o.pushKV("provenance_note", ProvenanceFor(m_plan));
    o.pushKV("authorship", "not implied by source integrity");
    o.pushKV("has_verified_manifest", m_verified.has_value());
    UniValue identity(UniValue::VOBJ);
    identity.pushKV("what", "cryptographic artifact; btx:// is the durable namespace");
    identity.pushKV("who", "native BTX publisher signatures remain; OpenSSF OMS/Sigstore/Cosign are extra evidence, never identity");
    identity.pushKV("money", "not required to fetch; monetary plane stays for spend, bounties, preservation");
    identity.pushKV("how", "distribution funding: free, private, BTX incentives, bounties, paid hosting; token is not an admission ticket to fetch");
    UniValue where(UniValue::VARR);
    for (const auto& origin : m_plan.origins) where.push_back(origin.type);
    if (where.empty()) where.push_back(KindName(m_plan.kind));
    identity.pushKV("where", where);
    identity.pushKV("run", "local capability evidence; not vendor naming");
    identity.pushKV("evidence", "BTX aggregates native publisher signatures plus OMS/Sigstore/Cosign/OCI attestations; it is not the sole CA");
    o.pushKV("identity", identity);
    UniValue origins(UniValue::VARR);
    for (const auto& origin : m_plan.origins) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("type", origin.type);
        e.pushKV("priority", origin.priority);
        origins.push_back(e);
    }
    o.pushKV("origins", origins);
    UniValue piece_origins(UniValue::VARR);
    for (const auto& origin : m_piece_origins) piece_origins.push_back(origin);
    o.pushKV("piece_origins", piece_origins);
    std::set<std::string> unique_bound(m_bound_piece_origins.begin(), m_bound_piece_origins.end());
    std::set<std::string> unique_all(m_piece_origins.begin(), m_piece_origins.end());
    const int independent = m_origins_mixed_without_identity
                                ? static_cast<int>(unique_bound.size())
                                : static_cast<int>((!unique_bound.empty() ? unique_bound : unique_all).size());
    o.pushKV("independent_origin_count", independent);
    o.pushKV("min_independent_origins", m_plan.min_independent_origins);
    o.pushKV("below_min_independent_origins",
             !m_piece_origins.empty() && independent < m_plan.min_independent_origins);
    o.pushKV("origins_mixed_without_identity", m_origins_mixed_without_identity);
    UniValue evidence(UniValue::VARR);
    for (const auto& pe : m_plan.provenance_evidence) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("kind", pe.kind);
        e.pushKV("role", pe.kind == "btx_publisher" ? "native_btx_publisher" : "additional_evidence");
        ProvenanceVerifyResult vr;
        (void)VerifyProvenanceEvidence(pe, vr);
        e.pushKV("verified_here", vr.verified_here);
        if (!vr.algorithm.empty()) e.pushKV("algorithm", vr.algorithm);
        if (!vr.error.empty()) e.pushKV("verify_error", vr.error);
        if (!pe.locator.empty()) e.pushKV("locator", pe.locator);
        if (!pe.note.empty()) e.pushKV("note", pe.note);
        evidence.push_back(e);
    }
    o.pushKV("provenance_evidence", evidence);
    UniValue cap(UniValue::VOBJ);
    cap.pushKV("readiness_target", "VERIFIED_FILES");
    cap.pushKV("inference", false);
    cap.pushKV("funded_wallet", false);
    cap.pushKV("automatic_spend_atoms", 0);
    cap.pushKV("authority", "local capability evidence; not vendor naming");
    o.pushKV("capability", cap);
    o.pushKV("wallet_required", false);
    o.pushKV("publisher_must_republish", false);
    o.pushKV("automatic_spend_atoms", 0);
    UniValue files(UniValue::VARR);
    for (const auto& f : m_accepted) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("destination_path", f.destination_path);
        e.pushKV("size_bytes", static_cast<int64_t>(f.size_bytes));
        files.push_back(e);
    }
    o.pushKV("files", files);
    if (m_verified) {
        o.pushKV("model_id", m_verified->model_id.Hex());
        o.pushKV("artifact_id", m_verified->artifact_id.Hex());
    }
    if (!m_fail_reason.empty()) o.pushKV("error", m_fail_reason);
    return o;
}

std::unique_ptr<ByteSource> MakePlanByteSource(const ImportPlan& plan, std::string& err)
{
    ImportPlan p = plan;
    SynthesizeOriginsFromV1(p);
    if (p.origins.size() > 1) {
        return std::make_unique<MultiOriginByteSource>(std::move(p));
    }
    if (p.kind == ImportSourceKind::LOCAL) {
        if (p.locator.empty()) {
            err = "locator";
            return nullptr;
        }
        return std::make_unique<LocalFileByteSource>(fs::PathFromString(p.locator));
    }
    if (p.kind == ImportSourceKind::HUGGINGFACE) {
        return std::make_unique<HuggingFaceByteSource>(p.locator, p.snapshot_token, /*follow_redirects=*/false);
    }
    if (p.kind == ImportSourceKind::TORRENT || p.kind == ImportSourceKind::MAGNET) {
        return std::make_unique<TorrentByteSource>(p.locator, p.snapshot_token, TorrentMapFromPlan(p));
    }
    if (p.kind == ImportSourceKind::S3) {
        ImportOrigin o;
        o.type = "s3";
        o.locator = p.locator;
        o.snapshot_token = p.snapshot_token;
        return std::make_unique<S3OriginByteSource>(std::move(o));
    }
    if (p.kind == ImportSourceKind::BTX) {
        ImportOrigin o;
        o.type = "btx";
        o.locator = p.locator;
        o.snapshot_token = p.snapshot_token;
        return std::make_unique<BtxOriginByteSource>(std::move(o));
    }
    if (ImportKindIsRegistry(p.kind) || p.kind == ImportSourceKind::HTTP) {
        ImportOrigin o;
        o.type = ImportOriginTypeName(p.kind);
        o.locator = p.locator;
        o.snapshot_token = p.snapshot_token;
        o.integrity = p.resolved_revision;
        return std::make_unique<RegistryByteSource>(std::move(o), p.live_wan);
    }
    err = "source adapter not in this module";
    return nullptr;
}

} // namespace modelnet
