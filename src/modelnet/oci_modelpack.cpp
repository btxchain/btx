// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/oci_modelpack.h>

#include <modelnet/import_plan.h>
#include <modelnet/store.h>

#include <algorithm>
#include <cstdlib>

namespace modelnet {
namespace {

std::string Str(const UniValue& o, const char* k)
{
    if (o.exists(k) && o[k].isStr()) return o[k].get_str();
    return {};
}

uint64_t U64(const UniValue& o, const char* k)
{
    if (!o.exists(k) || o[k].isNull()) return 0;
    if (o[k].isNum()) return o[k].getInt<uint64_t>();
    if (o[k].isStr()) return std::strtoull(o[k].get_str().c_str(), nullptr, 10);
    return 0;
}

void AddFileFromPart(const UniValue& part, ImportPlan& plan)
{
    ImportFileSpec spec;
    spec.source_path = Str(part, "path");
    if (spec.source_path.empty()) spec.source_path = Str(part, "name");
    spec.destination_path = spec.source_path;
    spec.size_bytes = U64(part, "size");
    if (spec.size_bytes == 0) spec.size_bytes = U64(part, "size_bytes");
    std::string digest = Str(part, "digest");
    if (digest.empty()) digest = Str(part, "sha384");
    if (digest.rfind("sha384:", 0) == 0) spec.sha384_hex = digest.substr(7);
    else if (digest.size() == 96 && digest.find(':') == std::string::npos) spec.sha384_hex = digest;
    if (spec.destination_path.empty()) return;
    std::string perr;
    if (!IsPortableRelPath(spec.destination_path, perr)) return;
    plan.files.push_back(std::move(spec));
}

} // namespace

bool ApplyModelPackConfig(const UniValue& config, ImportPlan& plan, std::string& err)
{
    if (!config.isObject()) {
        err = "modelpack";
        return false;
    }
    const std::string media = Str(config, "mediaType");
    if (!media.empty() && media.find("kitops") == std::string::npos && media.find("modelpack") == std::string::npos &&
        media.find("modelkit") == std::string::npos) {
        err = "modelpack mediaType";
        return false;
    }
    if (plan.kind == ImportSourceKind::LOCAL) plan.kind = ImportSourceKind::OCI;

    UniValue model = config.exists("model") && config["model"].isObject() ? config["model"] : UniValue(UniValue::VOBJ);
    if (config.exists("layers") && config["layers"].isArray()) {
        for (const auto& layer : config["layers"].getValues()) {
            if (layer.isObject()) AddFileFromPart(layer, plan);
        }
    }
    if (model.exists("parts") && model["parts"].isArray()) {
        for (const auto& part : model["parts"].getValues()) {
            if (part.isObject()) AddFileFromPart(part, plan);
        }
    }
    if (plan.files.empty()) {
        ImportFileSpec spec;
        spec.source_path = Str(model, "path");
        if (spec.source_path.empty()) spec.source_path = "model.safetensors";
        spec.destination_path = spec.source_path;
        spec.size_bytes = U64(model, "size");
        const std::string digest = Str(model, "digest");
        if (digest.rfind("sha384:", 0) == 0) spec.sha384_hex = digest.substr(7);
        std::string perr;
        if (!spec.destination_path.empty() && IsPortableRelPath(spec.destination_path, perr)) {
            plan.files.push_back(std::move(spec));
        }
    }

    if (plan.origins.empty() && config.exists("origin") && config["origin"].isObject()) {
        const UniValue& origin = config["origin"];
        ImportOrigin o;
        o.type = "oci";
        const std::string registry = Str(origin, "registry");
        const std::string repository = Str(origin, "repository");
        if (!registry.empty() && !repository.empty()) {
            o.locator = "oci://" + registry + "/" + repository;
        } else {
            o.locator = Str(origin, "locator");
        }
        o.snapshot_token = Str(origin, "digest");
        if (o.snapshot_token.empty()) o.snapshot_token = Str(origin, "snapshot_token");
        o.priority = 0;
        if (!o.locator.empty() && !o.snapshot_token.empty()) {
            plan.origins.push_back(std::move(o));
            plan.kind = ImportSourceKind::OCI;
            plan.locator = plan.origins.front().locator;
            plan.snapshot_token = plan.origins.front().snapshot_token;
        }
    }
    if (plan.provenance_note.empty()) {
        plan.provenance_note = "oci modelpack is an origin layout, not btx identity";
    }
    return true;
}

bool ExportModelPackConfig(const VerifiedManifest& vm, const ImportPlan& plan, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    if (vm.core.files.empty()) {
        err = "verified manifest files";
        return false;
    }
    out.pushKV("schemaVersion", "1.0.0");
    out.pushKV("mediaType", MODELPACK_MEDIA_TYPE);
    UniValue model(UniValue::VOBJ);
    model.pushKV("path", vm.core.files.front().path);
    model.pushKV("name", plan.plan_id.empty() ? vm.model_id.Hex() : plan.plan_id);
    UniValue parts(UniValue::VARR);
    for (const auto& cf : vm.core.files) {
        UniValue p(UniValue::VOBJ);
        p.pushKV("path", cf.path);
        p.pushKV("type", "model");
        p.pushKV("size", static_cast<int64_t>(cf.size));
        p.pushKV("digest", "sha384:" + cf.sha384.Hex());
        parts.push_back(p);
    }
    model.pushKV("parts", parts);
    out.pushKV("model", model);
    UniValue origin(UniValue::VOBJ);
    origin.pushKV("identity", "btx:// + VerifiedManifest; this layout is not the identity");
    if (!plan.origins.empty()) {
        origin.pushKV("type", plan.origins.front().type);
        origin.pushKV("locator", plan.origins.front().locator);
        origin.pushKV("digest", plan.origins.front().snapshot_token);
    }
    origin.pushKV("model_id", vm.model_id.Hex());
    origin.pushKV("artifact_id", vm.artifact_id.Hex());
    out.pushKV("origin", origin);
    out.pushKV("wallet_required", false);
    out.pushKV("publisher_must_republish", false);
    out.pushKV("automatic_spend_atoms", 0);
    return true;
}

} // namespace modelnet
