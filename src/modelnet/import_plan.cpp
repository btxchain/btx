// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/import_plan.h>

#include <modelnet/store.h>

#include <cstdlib>

namespace modelnet {

bool ImportSourceKindFromName(const std::string& name, ImportSourceKind& out)
{
    if (name == "LOCAL") {
        out = ImportSourceKind::LOCAL;
        return true;
    }
    if (name == "HUGGINGFACE") {
        out = ImportSourceKind::HUGGINGFACE;
        return true;
    }
    if (name == "TORRENT") {
        out = ImportSourceKind::TORRENT;
        return true;
    }
    if (name == "MAGNET") {
        out = ImportSourceKind::MAGNET;
        return true;
    }
    if (name == "BTX") {
        out = ImportSourceKind::BTX;
        return true;
    }
    if (name == "S3") {
        out = ImportSourceKind::S3;
        return true;
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
    }
    return "LOCAL";
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
    if (!json.exists("source") || !json["source"].isObject()) {
        err = "source";
        return false;
    }
    const UniValue& src = json["source"];
    if (!src.exists("kind") || !src["kind"].isStr() || !src.exists("locator") || !src["locator"].isStr() ||
        !src.exists("snapshot_token") || !src["snapshot_token"].isStr()) {
        err = "source fields";
        return false;
    }
    if (!ImportSourceKindFromName(src["kind"].get_str(), out.kind)) {
        err = "source kind";
        return false;
    }
    out.locator = src["locator"].get_str();
    out.snapshot_token = src["snapshot_token"].get_str();
    if (src.exists("resolved_revision") && src["resolved_revision"].isStr()) {
        out.resolved_revision = src["resolved_revision"].get_str();
    }
    if (src.exists("expected_btx_manifest") && src["expected_btx_manifest"].isStr()) {
        out.expected_btx_manifest = src["expected_btx_manifest"].get_str();
    }
    out.provenance_note = "source_integrity_only;not_publisher_authorship";
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
            out.files.push_back(std::move(spec));
        }
    }
    return true;
}

UniValue ImportPlanJson(const ImportPlan& plan)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("plan_id", plan.plan_id);
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", ImportSourceKindName(plan.kind));
    src.pushKV("locator", plan.locator);
    src.pushKV("snapshot_token", plan.snapshot_token);
    if (!plan.resolved_revision.empty()) src.pushKV("resolved_revision", plan.resolved_revision);
    if (!plan.expected_btx_manifest.empty()) src.pushKV("expected_btx_manifest", plan.expected_btx_manifest);
    o.pushKV("source", src);
    UniValue files(UniValue::VARR);
    for (const auto& f : plan.files) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("source_path", f.source_path);
        e.pushKV("destination_path", f.destination_path);
        e.pushKV("size_bytes", static_cast<int64_t>(f.size_bytes));
        files.push_back(e);
    }
    o.pushKV("files", files);
    o.pushKV("authorship", "not implied by source integrity");
    o.pushKV("provenance_note", plan.provenance_note);
    return o;
}

} // namespace modelnet
