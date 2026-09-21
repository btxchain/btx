// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/cloud_layout.h>

#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cstdint>
#include <cctype>
#include <string>

namespace modelnet {
namespace {

std::string LowerCopy(std::string_view s)
{
    return ToLower(s);
}

/** Host of an operator endpoint URL, or the raw string if it has no scheme. */
std::string EndpointHost(std::string_view endpoint)
{
    std::string s{endpoint};
    s = ToLower(util::TrimString(s));
    while (!s.empty() && s.back() == '.') s.pop_back();

    const auto scheme = s.find("://");
    std::string rest = scheme == std::string::npos ? s : s.substr(scheme + 3);
    const auto slash = rest.find_first_of("/?#");
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    const auto at = rest.rfind('@');
    if (at != std::string::npos) rest = rest.substr(at + 1);

    if (!rest.empty() && rest.front() == '[') {
        const auto br = rest.find(']');
        if (br == std::string::npos) return {};
        return rest.substr(1, br - 1);
    }
    const auto colon = rest.rfind(':');
    if (colon != std::string::npos) {
        bool port = true;
        for (size_t i = colon + 1; i < rest.size(); ++i) {
            if (!IsDigit(rest[i])) {
                port = false;
                break;
            }
        }
        if (port) rest = rest.substr(0, colon);
    }
    while (!rest.empty() && rest.back() == '.') rest.pop_back();
    return rest;
}

bool DnsLabelOk(std::string_view label)
{
    if (label.empty() || label.size() > 63) return false;
    for (unsigned char c : label) {
        if (!(std::isalnum(c) || c == '-')) return false;
    }
    return true;
}

std::string JoinPrefixRest(std::string_view prefix, std::string_view rest)
{
    std::string p{prefix};
    while (!p.empty() && (p.front() == '/' || p.front() == '\\')) p.erase(p.begin());
    while (!p.empty() && (p.back() == '/' || p.back() == '\\')) p.pop_back();
    if (p.empty()) return std::string{rest};
    return p + "/" + std::string{rest};
}

} // namespace

const char* CloudProviderName(CloudProvider p)
{
    switch (p) {
    case CloudProvider::AUTO: return "AUTO";
    case CloudProvider::GENERIC_S3: return "GENERIC_S3";
    case CloudProvider::AWS_S3: return "AWS_S3";
    case CloudProvider::CLOUDFLARE_R2: return "CLOUDFLARE_R2";
    case CloudProvider::MINIO: return "MINIO";
    }
    return "AUTO";
}

const char* CloudObjectLayoutName(CloudObjectLayout l)
{
    switch (l) {
    case CloudObjectLayout::AUTO: return "AUTO";
    case CloudObjectLayout::SOURCE_FILES: return "SOURCE_FILES";
    case CloudObjectLayout::PIECE_OBJECTS: return "PIECE_OBJECTS";
    }
    return "AUTO";
}

const char* CloudReadStrategyName(CloudReadStrategy s)
{
    switch (s) {
    case CloudReadStrategy::AUTO: return "AUTO";
    case CloudReadStrategy::STREAM_FILE: return "STREAM_FILE";
    case CloudReadStrategy::PIECE_GET: return "PIECE_GET";
    }
    return "AUTO";
}

bool CloudProviderFromName(std::string_view name, CloudProvider& out)
{
    const std::string n = LowerCopy(name);
    if (n == "auto") {
        out = CloudProvider::AUTO;
        return true;
    }
    if (n == "generic_s3" || n == "generic-s3" || n == "s3") {
        out = CloudProvider::GENERIC_S3;
        return true;
    }
    if (n == "aws_s3" || n == "aws-s3" || n == "aws") {
        out = CloudProvider::AWS_S3;
        return true;
    }
    if (n == "cloudflare_r2" || n == "cloudflare-r2" || n == "r2") {
        out = CloudProvider::CLOUDFLARE_R2;
        return true;
    }
    if (n == "minio") {
        out = CloudProvider::MINIO;
        return true;
    }
    return false;
}

bool CloudObjectLayoutFromName(std::string_view name, CloudObjectLayout& out)
{
    const std::string n = LowerCopy(name);
    if (n == "auto") {
        out = CloudObjectLayout::AUTO;
        return true;
    }
    if (n == "source_files" || n == "source-files") {
        out = CloudObjectLayout::SOURCE_FILES;
        return true;
    }
    if (n == "piece_objects" || n == "piece-objects") {
        out = CloudObjectLayout::PIECE_OBJECTS;
        return true;
    }
    return false;
}

bool CloudReadStrategyFromName(std::string_view name, CloudReadStrategy& out)
{
    const std::string n = LowerCopy(name);
    if (n == "auto") {
        out = CloudReadStrategy::AUTO;
        return true;
    }
    if (n == "stream_file" || n == "stream-file") {
        out = CloudReadStrategy::STREAM_FILE;
        return true;
    }
    if (n == "piece_get" || n == "piece-get") {
        out = CloudReadStrategy::PIECE_GET;
        return true;
    }
    return false;
}

bool EndpointLooksLikeCloudflareR2(std::string_view endpoint)
{
    const std::string host = EndpointHost(endpoint);
    if (host.empty()) return false;
    if (host == "r2.cloudflarestorage.com") return true;
    constexpr std::string_view suffix = ".r2.cloudflarestorage.com";
    if (host.size() <= suffix.size()) return false;
    if (!host.ends_with(suffix)) return false;
    const std::string labels = host.substr(0, host.size() - suffix.size());
    if (labels.empty() || labels.front() == '.' || labels.back() == '.') return false;
    size_t start = 0;
    while (start < labels.size()) {
        const size_t dot = labels.find('.', start);
        const std::string_view lab = std::string_view{labels}.substr(
            start, (dot == std::string::npos ? labels.size() : dot) - start);
        if (!DnsLabelOk(lab)) return false;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return true;
}

bool CloudProviderIsR2(CloudProvider provider, std::string_view endpoint)
{
    if (provider == CloudProvider::CLOUDFLARE_R2) return true;
    if (provider == CloudProvider::AUTO && EndpointLooksLikeCloudflareR2(endpoint)) return true;
    return false;
}

bool ResolveCloudLayout(CloudProvider provider,
                        std::string_view endpoint,
                        CloudObjectLayout explicit_layout,
                        bool allow_request_heavy,
                        uint64_t projected_piece_objects,
                        CloudObjectLayout& out_layout,
                        CloudReadStrategy& out_strategy,
                        std::string& reject_reason)
{
    reject_reason.clear();
    const bool r2 = CloudProviderIsR2(provider, endpoint);

    if (explicit_layout == CloudObjectLayout::AUTO) {
        out_layout = CloudObjectLayout::SOURCE_FILES;
        out_strategy = CloudReadStrategy::STREAM_FILE;
    } else {
        out_layout = explicit_layout;
        out_strategy = (explicit_layout == CloudObjectLayout::PIECE_OBJECTS)
                           ? CloudReadStrategy::PIECE_GET
                           : CloudReadStrategy::STREAM_FILE;
    }

    if (r2 && out_layout == CloudObjectLayout::PIECE_OBJECTS && !allow_request_heavy &&
        projected_piece_objects > kR2HeavyPieceObjectThreshold) {
        const uint64_t gets = EstimatedGetsPerColdRetrieval(CloudObjectLayout::PIECE_OBJECTS, /*n_files=*/1,
                                                            projected_piece_objects);
        reject_reason = strprintf(
            "PIECE_OBJECTS on Cloudflare R2 would issue %d origin GETs per cold retrieval "
            "(threshold %d); set allow_request_heavy_cloud_layout to override",
            static_cast<int64_t>(gets), static_cast<int64_t>(kR2HeavyPieceObjectThreshold));
        return false;
    }
    return true;
}

uint64_t EstimatedGetsPerColdRetrieval(CloudObjectLayout layout, uint64_t n_files, uint64_t n_pieces)
{
    if (layout == CloudObjectLayout::PIECE_OBJECTS) return n_pieces;
    return n_files;
}

std::string ObjectKeySourceFile(std::string_view prefix, std::string_view artifact_hex, uint32_t file_index)
{
    const std::string rest = "artifacts/" + std::string{artifact_hex} + "/files/" + std::to_string(file_index);
    return JoinPrefixRest(prefix, rest);
}

std::string ObjectKeyPiece(std::string_view prefix, std::string_view artifact_hex, uint32_t file_index, uint32_t piece_index)
{
    const std::string rest = "artifacts/" + std::string{artifact_hex} + "/" + std::to_string(file_index) + "/" +
                             std::to_string(piece_index) + ".piece";
    return JoinPrefixRest(prefix, rest);
}

bool NormalizeCloudKeyPrefix(std::string_view prefix, std::string& out, std::string& err)
{
    out.clear();
    std::string s{prefix};
    while (!s.empty() && (s.front() == '/' || s.front() == '\\')) s.erase(s.begin());
    while (!s.empty() && (s.back() == '/' || s.back() == '\\')) s.pop_back();
    if (s.find("..") != std::string::npos) {
        err = "cloud prefix must not contain ..";
        return false;
    }
    if (s.find("://") != std::string::npos) {
        err = "cloud prefix must not contain a URL";
        return false;
    }
    for (unsigned char c : s) {
        if (!(std::isalnum(c) || c == '/' || c == '.' || c == '_' || c == '-')) {
            err = "cloud prefix has invalid character";
            return false;
        }
    }
    out = std::move(s);
    return true;
}

} // namespace modelnet
