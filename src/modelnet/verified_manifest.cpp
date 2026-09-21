// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/verified_manifest.h>

#include <crypto/sha384.h>
#include <modelnet/safety.h>
#include <modelnet/store.h>
#include <modelnet/types.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>

namespace modelnet {

bool VerifyManifestAgainstRequest(const UniValue& manifest, VerifiedManifest& out, std::string& err)
{
    out = {};
    if (!manifest.isObject()) {
        err = "manifest json";
        return false;
    }
    if (!manifest.exists("model_id") || !manifest["model_id"].isStr() ||
        !manifest.exists("artifact_id") || !manifest["artifact_id"].isStr()) {
        err = "manifest ids";
        return false;
    }
    Digest48 claimed_model, claimed_artifact;
    if (!Digest48::FromHex(manifest["model_id"].get_str(), claimed_model, err)) return false;
    if (!Digest48::FromHex(manifest["artifact_id"].get_str(), claimed_artifact, err)) return false;
    if (!manifest.exists("files") || !manifest["files"].isArray()) {
        err = "manifest files";
        return false;
    }
    const auto files = manifest["files"].getValues();
    if (files.empty() || files.size() > 1024) {
        err = "file count";
        return false;
    }

    ModelCore core;
    core.version = 2;
    if (manifest.exists("format_profile") && manifest["format_profile"].isNum()) {
        core.format_profile = static_cast<uint16_t>(manifest["format_profile"].getInt<int>());
    }
    if (manifest.exists("execution_profile") && manifest["execution_profile"].isNum()) {
        core.execution_profile = static_cast<uint16_t>(manifest["execution_profile"].getInt<int>());
    }
    std::set<std::string> lower_paths;
    std::string prev_path;
    bool first = true;
    for (const auto& f : files) {
        if (!f.isObject()) {
            err = "manifest file";
            return false;
        }
        CoreFile cf;
        if (!f.exists("path") || !f["path"].isStr() || !f.exists("role") || !f["role"].isStr() ||
            !f.exists("size") || !f["size"].isNum() || !f.exists("sha384") || !f["sha384"].isStr() ||
            !f.exists("pieces_root") || !f["pieces_root"].isStr()) {
            err = "manifest file fields";
            return false;
        }
        cf.path = f["path"].get_str();
        if (!IsPortableRelPath(cf.path, err)) return false;
        if (RelPathLooksUnsafe(cf.path)) {
            err = "skipped unsafe or unsupported name";
            return false;
        }
        if (!FileRoleFromName(f["role"].get_str(), cf.role)) {
            err = "role";
            return false;
        }
        if (f["size"].getInt<int64_t>() < 0) {
            err = "file size";
            return false;
        }
        cf.size = f["size"].getInt<uint64_t>();
        if (!Digest48::FromHex(f["sha384"].get_str(), cf.sha384, err)) return false;
        if (!Digest48::FromHex(f["pieces_root"].get_str(), cf.pieces_root, err)) return false;
        std::string lower = cf.path;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        if (!lower_paths.insert(lower).second) {
            err = "duplicate path";
            return false;
        }
        if (!first && cf.path < prev_path) {
            err = "path ordering";
            return false;
        }
        first = false;
        prev_path = cf.path;
        if (cf.role == FileRole::CONFIG && core.config_sha384.IsNull()) core.config_sha384 = cf.sha384;
        if (cf.role == FileRole::TOKENIZER && core.tokenizer_sha384.IsNull()) core.tokenizer_sha384 = cf.sha384;
        core.files.push_back(std::move(cf));
    }

    std::vector<unsigned char> encoded;
    if (!EncodeModelCore(core, encoded, err)) return false;
    const Digest48 model_id = ModelCoreId(encoded);
    if (model_id != claimed_model) {
        err = "ID_MISMATCH";
        return false;
    }

    ArtifactCore artifact;
    artifact.version = 2;
    artifact.codec = 1;
    artifact.model_id = model_id;
    artifact.files = core.files;
    std::vector<unsigned char> aenc;
    if (!EncodeArtifactCore(artifact, aenc, err)) return false;
    const Digest48 artifact_id = ArtifactCoreId(aenc);
    if (artifact_id != claimed_artifact) {
        err = "ID_MISMATCH";
        return false;
    }

    out.core = std::move(core);
    out.artifact = std::move(artifact);
    out.model_id = model_id;
    out.artifact_id = artifact_id;
    return true;
}

bool VerifyManifestAgainstRequest(const UniValue& manifest, const Digest48& requested,
                                  VerifiedManifest& out, std::string& err)
{
    if (!VerifyManifestAgainstRequest(manifest, out, err)) return false;
    if (requested != out.model_id && requested != out.artifact_id) {
        out = {};
        err = "ID_MISMATCH";
        return false;
    }
    return true;
}

bool HashFileSha384AndPiecesRoot(const fs::path& path, Digest48& sha384, Digest48& pieces_root, uint64_t& size,
                                 std::string& err)
{
    sha384 = {};
    pieces_root = {};
    size = 0;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "staged file missing";
        return false;
    }
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    size = bytes.size();
    CSHA384 h;
    if (!bytes.empty()) h.Write(bytes.data(), bytes.size());
    h.Finalize(sha384.data.data());
    const auto tree = BuildChunkTree(Span<const unsigned char>{bytes.data(), bytes.size()});
    if (tree.empty() || tree.back().empty()) {
        err = "pieces_root";
        return false;
    }
    pieces_root = tree.back().front();
    return true;
}

bool BindVerifiedManifestToStaged(const VerifiedManifest& claimed, const fs::path& stage_dir, std::string& err)
{
    if (claimed.model_id.IsNull() || claimed.artifact_id.IsNull()) {
        err = "verified manifest ids";
        return false;
    }
    if (claimed.core.files.empty()) {
        err = "verified manifest files";
        return false;
    }
    std::vector<unsigned char> encoded;
    if (!EncodeModelCore(claimed.core, encoded, err)) return false;
    if (ModelCoreId(encoded) != claimed.model_id) {
        err = "ID_MISMATCH";
        return false;
    }
    ArtifactCore art = claimed.artifact;
    if (art.files.empty()) {
        art.version = 2;
        art.codec = 1;
        art.model_id = claimed.model_id;
        art.files = claimed.core.files;
    }
    std::vector<unsigned char> aenc;
    if (!EncodeArtifactCore(art, aenc, err)) return false;
    if (ArtifactCoreId(aenc) != claimed.artifact_id) {
        err = "ID_MISMATCH";
        return false;
    }
    for (const auto& cf : claimed.core.files) {
        Digest48 sha, root;
        uint64_t sz = 0;
        if (!HashFileSha384AndPiecesRoot(stage_dir / fs::PathFromString(cf.path), sha, root, sz, err)) return false;
        if (sz != cf.size || sha != cf.sha384 || root != cf.pieces_root) {
            err = "HASH_MISMATCH";
            return false;
        }
    }
    return true;
}

bool MakeVerifiedManifestFromStaged(const fs::path& stage_dir, const std::vector<std::string>& rel_paths,
                                    VerifiedManifest& out, std::string& err)
{
    out = {};
    if (rel_paths.empty()) {
        err = "verified manifest files";
        return false;
    }
    ModelCore core;
    core.version = 2;
    core.format_profile = 1;
    for (const auto& rel : rel_paths) {
        CoreFile cf;
        cf.path = rel;
        cf.role = FileRole::WEIGHTS;
        if (!HashFileSha384AndPiecesRoot(stage_dir / fs::PathFromString(rel), cf.sha384, cf.pieces_root, cf.size, err)) {
            return false;
        }
        core.files.push_back(std::move(cf));
    }
    std::vector<unsigned char> encoded;
    if (!EncodeModelCore(core, encoded, err)) return false;
    out.model_id = ModelCoreId(encoded);
    ArtifactCore artifact;
    artifact.version = 2;
    artifact.codec = 1;
    artifact.model_id = out.model_id;
    artifact.files = core.files;
    std::vector<unsigned char> aenc;
    if (!EncodeArtifactCore(artifact, aenc, err)) return false;
    out.artifact_id = ArtifactCoreId(aenc);
    out.core = std::move(core);
    out.artifact = std::move(artifact);
    return true;
}

} // namespace modelnet
