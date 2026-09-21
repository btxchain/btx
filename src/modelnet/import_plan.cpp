// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/import_plan.h>

#include <modelnet/store.h>

#include <algorithm>
#include <cstdlib>

namespace modelnet {
namespace {

struct KindRow {
    const char* name;
    ImportSourceKind kind;
    const char* origin_type;
};

const KindRow kKinds[] = {
    {"LOCAL", ImportSourceKind::LOCAL, "local"},
    {"HUGGINGFACE", ImportSourceKind::HUGGINGFACE, "huggingface"},
    {"HF", ImportSourceKind::HUGGINGFACE, "huggingface"},
    {"TORRENT", ImportSourceKind::TORRENT, "torrent"},
    {"MAGNET", ImportSourceKind::MAGNET, "magnet"},
    {"BTX", ImportSourceKind::BTX, "btx"},
    {"S3", ImportSourceKind::S3, "s3"},
    {"HTTP", ImportSourceKind::HTTP, "http"},
    {"HTTPS", ImportSourceKind::HTTP, "http"},
    {"MODELSCOPE", ImportSourceKind::MODELSCOPE, "modelscope"},
    {"WISEMODEL", ImportSourceKind::WISEMODEL, "wisemodel"},
    {"OPENXLAB", ImportSourceKind::OPENXLAB, "openxlab"},
    {"MODELERS", ImportSourceKind::MODELERS, "modelers"},
    {"GITCODE", ImportSourceKind::GITCODE, "gitcode"},
    {"GITEE", ImportSourceKind::GITEE, "gitee"},
    {"OPENI", ImportSourceKind::OPENI, "openi"},
    {"HF_MIRROR", ImportSourceKind::HF_MIRROR, "hf-mirror"},
    {"HFMIRROR", ImportSourceKind::HF_MIRROR, "hf-mirror"},
    {"OCI", ImportSourceKind::OCI, "oci"},
    {"KITOPS", ImportSourceKind::OCI, "oci"},
    {"MODELPACK", ImportSourceKind::OCI, "oci"},
};

std::string UpperCopy(std::string s)
{
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

std::string LowerCopy(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

} // namespace

bool ImportSourceKindFromName(const std::string& name, ImportSourceKind& out)
{
    const std::string u = UpperCopy(name);
    for (const auto& row : kKinds) {
        if (u == row.name) {
            out = row.kind;
            return true;
        }
    }
    return false;
}

const char* ImportSourceKindName(ImportSourceKind k)
{
    switch (k) {
    case ImportSourceKind::LOCAL: return "LOCAL";
    case ImportSourceKind::HUGGINGFACE: return "HUGGINGFACE";
    case ImportSourceKind::TORRENT: return "TORRENT";
    case ImportSourceKind::MAGNET: return "MAGNET";
    case ImportSourceKind::BTX: return "BTX";
    case ImportSourceKind::S3: return "S3";
    case ImportSourceKind::HTTP: return "HTTP";
    case ImportSourceKind::MODELSCOPE: return "MODELSCOPE";
    case ImportSourceKind::WISEMODEL: return "WISEMODEL";
    case ImportSourceKind::OPENXLAB: return "OPENXLAB";
    case ImportSourceKind::MODELERS: return "MODELERS";
    case ImportSourceKind::GITCODE: return "GITCODE";
    case ImportSourceKind::GITEE: return "GITEE";
    case ImportSourceKind::OPENI: return "OPENI";
    case ImportSourceKind::HF_MIRROR: return "HF_MIRROR";
    case ImportSourceKind::OCI: return "OCI";
    }
    return "LOCAL";
}

const char* ImportOriginTypeName(ImportSourceKind k)
{
    switch (k) {
    case ImportSourceKind::LOCAL: return "local";
    case ImportSourceKind::HUGGINGFACE: return "huggingface";
    case ImportSourceKind::TORRENT: return "torrent";
    case ImportSourceKind::MAGNET: return "magnet";
    case ImportSourceKind::BTX: return "btx";
    case ImportSourceKind::S3: return "s3";
    case ImportSourceKind::HTTP: return "http";
    case ImportSourceKind::MODELSCOPE: return "modelscope";
    case ImportSourceKind::WISEMODEL: return "wisemodel";
    case ImportSourceKind::OPENXLAB: return "openxlab";
    case ImportSourceKind::MODELERS: return "modelers";
    case ImportSourceKind::GITCODE: return "gitcode";
    case ImportSourceKind::GITEE: return "gitee";
    case ImportSourceKind::OPENI: return "openi";
    case ImportSourceKind::HF_MIRROR: return "hf-mirror";
    case ImportSourceKind::OCI: return "oci";
    }
    return "local";
}

bool ImportOriginTypeFromName(const std::string& name, std::string& canonical)
{
    ImportSourceKind k;
    if (!ImportSourceKindFromName(name, k)) {
        // already-canonical origin types
        const std::string lower = LowerCopy(name);
        for (const auto& row : kKinds) {
            if (lower == row.origin_type) {
                canonical = row.origin_type;
                return true;
            }
        }
        return false;
    }
    canonical = ImportOriginTypeName(k);
    return true;
}

bool ImportKindIsRegistry(ImportSourceKind k)
{
    switch (k) {
    case ImportSourceKind::HUGGINGFACE:
    case ImportSourceKind::HTTP:
    case ImportSourceKind::MODELSCOPE:
    case ImportSourceKind::WISEMODEL:
    case ImportSourceKind::OPENXLAB:
    case ImportSourceKind::MODELERS:
    case ImportSourceKind::GITCODE:
    case ImportSourceKind::GITEE:
    case ImportSourceKind::OPENI:
    case ImportSourceKind::HF_MIRROR:
    case ImportSourceKind::OCI:
        return true;
    default:
        return false;
    }
}

void SynthesizeOriginsFromV1(ImportPlan& plan)
{
    if (!plan.origins.empty()) return;
    ImportOrigin o;
    o.type = ImportOriginTypeName(plan.kind);
    o.locator = plan.locator;
    o.snapshot_token = plan.snapshot_token;
    o.integrity = plan.resolved_revision;
    o.priority = 0;
    plan.origins.push_back(std::move(o));
}

bool ParseImportPlan(const UniValue& json, ImportPlan& out, std::string& err)
{
    out = {};
    if (!json.isObject()) {
        err = "import plan json";
        return false;
    }
    if (!json.exists("plan_id") || !json["plan_id"].isStr()) {
        err = "plan_id";
        return false;
    }
    out.plan_id = json["plan_id"].get_str();
    if (out.plan_id.size() != 96) {
        err = "plan_id";
        return false;
    }
    if (json.exists("live_wan")) {
        if (json["live_wan"].isBool()) out.live_wan = json["live_wan"].get_bool();
        else if (json["live_wan"].isNum()) out.live_wan = json["live_wan"].getInt<int>() != 0;
    }
    if (json.exists("min_independent_origins") && !json["min_independent_origins"].isNull()) {
        int n = 1;
        if (json["min_independent_origins"].isNum()) n = json["min_independent_origins"].getInt<int>();
        else if (json["min_independent_origins"].isStr()) {
            n = std::atoi(json["min_independent_origins"].get_str().c_str());
        } else {
            err = "min_independent_origins";
            return false;
        }
        if (n < 1) {
            err = "min_independent_origins";
            return false;
        }
        out.min_independent_origins = n;
    }

    auto parse_origin = [&](const UniValue& src, ImportOrigin& origin, ImportSourceKind* kind_out) -> bool {
        if (!src.isObject()) {
            err = "origin";
            return false;
        }
        const bool has_type = src.exists("type") && src["type"].isStr();
        const bool has_kind = src.exists("kind") && src["kind"].isStr();
        if (!has_type && !has_kind) {
            err = "origin type";
            return false;
        }
        if (!src.exists("locator") || !src["locator"].isStr() || !src.exists("snapshot_token") ||
            !src["snapshot_token"].isStr()) {
            err = "source fields";
            return false;
        }
        ImportSourceKind k = ImportSourceKind::HTTP;
        if (has_kind && !ImportSourceKindFromName(src["kind"].get_str(), k)) {
            err = "source kind";
            return false;
        }
        if (has_type) {
            std::string canon;
            if (!ImportOriginTypeFromName(src["type"].get_str(), canon)) {
                err = "origin type";
                return false;
            }
            origin.type = std::move(canon);
            if (!has_kind) (void)ImportSourceKindFromName(origin.type, k);
        } else {
            origin.type = ImportOriginTypeName(k);
        }
        origin.locator = src["locator"].get_str();
        origin.snapshot_token = src["snapshot_token"].get_str();
        if (src.exists("integrity") && src["integrity"].isStr()) origin.integrity = src["integrity"].get_str();
        else if (src.exists("resolved_revision") && src["resolved_revision"].isStr()) {
            origin.integrity = src["resolved_revision"].get_str();
        }
        if (src.exists("priority")) {
            if (src["priority"].isNum()) origin.priority = src["priority"].getInt<int>();
            else if (src["priority"].isStr()) origin.priority = std::atoi(src["priority"].get_str().c_str());
        }
        if (kind_out) *kind_out = k;
        return true;
    };

    if (json.exists("origins") && json["origins"].isArray()) {
        for (const auto& item : json["origins"].getValues()) {
            ImportOrigin origin;
            ImportSourceKind k = ImportSourceKind::HTTP;
            if (!parse_origin(item, origin, &k)) return false;
            out.origins.push_back(std::move(origin));
            if (out.origins.size() == 1) {
                out.kind = k;
                out.locator = out.origins.front().locator;
                out.snapshot_token = out.origins.front().snapshot_token;
                out.resolved_revision = out.origins.front().integrity;
            }
        }
        if (out.origins.empty()) {
            err = "origins";
            return false;
        }
        std::stable_sort(out.origins.begin(), out.origins.end(),
                         [](const ImportOrigin& a, const ImportOrigin& b) { return a.priority < b.priority; });
    }

    if (json.exists("source") && json["source"].isObject()) {
        const UniValue& src = json["source"];
        ImportOrigin origin;
        ImportSourceKind k = ImportSourceKind::LOCAL;
        if (!parse_origin(src, origin, &k)) return false;
        out.kind = k;
        out.locator = origin.locator;
        out.snapshot_token = origin.snapshot_token;
        if (src.exists("resolved_revision") && src["resolved_revision"].isStr()) {
            out.resolved_revision = src["resolved_revision"].get_str();
            if (origin.integrity.empty()) origin.integrity = out.resolved_revision;
        }
        if (src.exists("expected_btx_manifest") && src["expected_btx_manifest"].isStr()) {
            out.expected_btx_manifest = src["expected_btx_manifest"].get_str();
        }
        if (out.origins.empty()) out.origins.push_back(std::move(origin));
    } else if (out.origins.empty()) {
        err = "source";
        return false;
    }

    if (json.exists("expected_btx_manifest") && json["expected_btx_manifest"].isStr()) {
        out.expected_btx_manifest = json["expected_btx_manifest"].get_str();
    }
    out.provenance_note = "source_integrity_only;not_publisher_authorship";
    SynthesizeOriginsFromV1(out);
    if (json.exists("files") && json["files"].isArray()) {
        for (const auto& f : json["files"].getValues()) {
            if (!f.isObject()) continue;
            ImportFileSpec spec;
            if (f.exists("source_path") && f["source_path"].isStr()) spec.source_path = f["source_path"].get_str();
            if (f.exists("destination_path") && f["destination_path"].isStr()) {
                spec.destination_path = f["destination_path"].get_str();
            } else {
                spec.destination_path = spec.source_path;
            }
            std::string perr;
            if (!spec.destination_path.empty() && !IsPortableRelPath(spec.destination_path, perr)) {
                err = perr;
                return false;
            }
            if (f.exists("size_bytes")) {
                if (f["size_bytes"].isNum()) spec.size_bytes = f["size_bytes"].getInt<uint64_t>();
                else if (f["size_bytes"].isStr()) {
                    spec.size_bytes = std::strtoull(f["size_bytes"].get_str().c_str(), nullptr, 10);
                }
            }
            if (f.exists("sha384") && f["sha384"].isStr()) spec.sha384_hex = f["sha384"].get_str();
            else if (f.exists("sha384_hex") && f["sha384_hex"].isStr()) spec.sha384_hex = f["sha384_hex"].get_str();
            if (f.exists("piece_sha384") && f["piece_sha384"].isArray()) {
                for (const auto& p : f["piece_sha384"].getValues()) {
                    if (p.isStr()) spec.piece_sha384_hex.push_back(p.get_str());
                }
            }
            out.files.push_back(std::move(spec));
        }
    }
    out.wallet_required = false; // fetch is walletless; monetary plane remains for spend/bounties
    if (json.exists("provenance_evidence") && json["provenance_evidence"].isArray()) {
        for (const auto& e : json["provenance_evidence"].getValues()) {
            if (!e.isObject()) continue;
            ProvenanceEvidence pe;
            if (e.exists("kind") && e["kind"].isStr()) pe.kind = LowerCopy(e["kind"].get_str());
            if (e.exists("locator") && e["locator"].isStr()) pe.locator = e["locator"].get_str();
            if (e.exists("note") && e["note"].isStr()) pe.note = e["note"].get_str();
            if (pe.kind != "btx_publisher" && pe.kind != "openssf_oms" && pe.kind != "sigstore" &&
                pe.kind != "cosign" && pe.kind != "unsigned" && pe.kind != "oci_attestation" &&
                pe.kind != "vendor_attestation") {
                err = "provenance kind";
                return false;
            }
            out.provenance_evidence.push_back(std::move(pe));
        }
    }
    return true;
}

UniValue ImportPlanJson(const ImportPlan& plan)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", plan.origins.size() > 1 ? 2 : 1);
    o.pushKV("plan_id", plan.plan_id);
    o.pushKV("live_wan", plan.live_wan);
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", ImportSourceKindName(plan.kind));
    src.pushKV("locator", plan.locator);
    src.pushKV("snapshot_token", plan.snapshot_token);
    if (!plan.resolved_revision.empty()) src.pushKV("resolved_revision", plan.resolved_revision);
    if (!plan.expected_btx_manifest.empty()) src.pushKV("expected_btx_manifest", plan.expected_btx_manifest);
    o.pushKV("source", src);
    UniValue origins(UniValue::VARR);
    for (const auto& origin : plan.origins) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("type", origin.type);
        e.pushKV("locator", origin.locator);
        e.pushKV("snapshot_token", origin.snapshot_token);
        if (!origin.integrity.empty()) e.pushKV("integrity", origin.integrity);
        e.pushKV("priority", origin.priority);
        origins.push_back(e);
    }
    o.pushKV("origins", origins);
    UniValue files(UniValue::VARR);
    for (const auto& f : plan.files) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("source_path", f.source_path);
        e.pushKV("destination_path", f.destination_path);
        e.pushKV("size_bytes", static_cast<int64_t>(f.size_bytes));
        if (!f.sha384_hex.empty()) e.pushKV("sha384", f.sha384_hex);
        if (!f.piece_sha384_hex.empty()) {
            UniValue leaves(UniValue::VARR);
            for (const auto& leaf : f.piece_sha384_hex) leaves.push_back(leaf);
            e.pushKV("piece_sha384", leaves);
        }
        files.push_back(e);
    }
    o.pushKV("files", files);
    o.pushKV("wallet_required", false);
    o.pushKV("publisher_must_republish", false);
    o.pushKV("min_independent_origins", plan.min_independent_origins);
    UniValue ev(UniValue::VARR);
    for (const auto& pe : plan.provenance_evidence) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("kind", pe.kind);
        if (!pe.locator.empty()) e.pushKV("locator", pe.locator);
        if (!pe.note.empty()) e.pushKV("note", pe.note);
        ev.push_back(e);
    }
    o.pushKV("provenance_evidence", ev);
    o.pushKV("authorship", "not implied by source integrity");
    o.pushKV("provenance_note", plan.provenance_note);
    return o;
}

} // namespace modelnet
