// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/import_coordinator.h>

#include <modelnet/import_plan.h>
#include <modelnet/io_executor.h>
#include <modelnet/qualification.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_local.h>
#include <modelnet/source_torrent.h>
#include <modelnet/store.h>
#include <random.h>
#include <span.h>
#include <util/strencodings.h>

#include <fstream>

namespace modelnet {
namespace {

const char* KindName(ImportSourceKind k)
{
    switch (k) {
    case ImportSourceKind::LOCAL: return "LOCAL";
    case ImportSourceKind::HUGGINGFACE: return "HUGGINGFACE";
    case ImportSourceKind::TORRENT: return "TORRENT";
    case ImportSourceKind::MAGNET: return "MAGNET";
    case ImportSourceKind::BTX: return "BTX";
    case ImportSourceKind::S3: return "S3";
    }
    return "LOCAL";
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
    std::vector<unsigned char> bytes;
    IoExecutor io(1);
    if (!io.Submit(err)) return false;
    const bool got = src.Read({0, spec.size_bytes}, bytes, budget_bytes, err);
    io.Complete();
    if (!got) return false;
    if (LooksLikePickle(bytes) || LooksLikeExecutable(dest, bytes)) {
        err = "pickle/.pt execution forbidden";
        return false;
    }
    const fs::path outp = StagingDir() / fs::PathFromString(dest);
    fs::create_directories(outp.parent_path());
    std::ofstream out(outp, std::ios::binary);
    if (!out) {
        err = "open";
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    if (!out) {
        err = "write";
        return false;
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
    if (plan.kind == ImportSourceKind::LOCAL) {
        if (plan.locator.empty()) {
            err = "locator";
            return nullptr;
        }
        return std::make_unique<LocalFileByteSource>(fs::PathFromString(plan.locator));
    }
    if (plan.kind == ImportSourceKind::HUGGINGFACE) {
        return std::make_unique<HuggingFaceByteSource>(plan.locator, plan.snapshot_token, /*follow_redirects=*/false);
    }
    if (plan.kind == ImportSourceKind::TORRENT || plan.kind == ImportSourceKind::MAGNET) {
        return std::make_unique<TorrentByteSource>(plan.locator, plan.snapshot_token, TorrentMapFromPlan(plan));
    }
    err = "source adapter not in this module";
    return nullptr;
}

} // namespace modelnet
