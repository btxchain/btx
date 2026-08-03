// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <matmul-rc-production-golden-manifest-data.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace matmul::v4::rc {
namespace {

constexpr std::string_view MANIFEST_MAGIC{"BTX_RC_PRODUCTION_GOLDEN_V1"};
constexpr size_t MANIFEST_FIELDS{10};

bool IsSafeToken(const std::string_view value)
{
    return !value.empty() && std::all_of(value.begin(), value.end(), [](const unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_' || c == '.';
    });
}

bool IsSafePublicPath(const std::string_view value)
{
    return value.starts_with("doc/evidence/") &&
        std::all_of(value.begin(), value.end(), [](const unsigned char c) {
            return std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '/';
        });
}

bool ExactHex(const std::string_view value, const size_t chars)
{
    return value.size() == chars && IsHex(value);
}

} // namespace

std::vector<RCProductionGoldenManifestEntry>
ParseRCProductionGoldenManifestData(std::string_view encoded)
{
    if (!encoded.empty() && encoded.back() == '\n') encoded.remove_suffix(1);
    const std::vector<std::string> lines{util::SplitString(encoded, '\n')};
    if (lines.size() < 3 || lines.front() != MANIFEST_MAGIC) return {};

    std::vector<RCProductionGoldenManifestEntry> manifest;
    manifest.reserve(lines.size() - 1);
    for (size_t line_index{1}; line_index < lines.size(); ++line_index) {
        const std::vector<std::string> fields{util::SplitString(lines[line_index], '|')};
        if (fields.size() != MANIFEST_FIELDS ||
            !IsSafeToken(fields[0]) || !IsSafeToken(fields[1]) ||
            !IsSafeToken(fields[2]) || fields[5] != "1" ||
            !IsSafePublicPath(fields[6]) || !ExactHex(fields[4], 64) ||
            !ExactHex(fields[7], 40) || !ExactHex(fields[8], 64) ||
            !ExactHex(fields[9], 64)) {
            return {};
        }

        uint64_t nonce{0};
        if (!ParseUInt64(fields[3], &nonce)) return {};
        const auto digest{uint256::FromHex(fields[4])};
        if (!digest) return {};

        manifest.push_back(RCProductionGoldenManifestEntry{
            .id = fields[0],
            .provider_class = {.provider_family = fields[1],
                               .device_architecture = fields[2]},
            .epoch = {.activation_height =
                          RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT,
                      .profile = 1,
                      .transcript_version = kRCTranscriptVersion,
                      .matmul_dimension = 4096,
                      .params = DefaultConsensusRCEpisodeParams()},
            .header_nonce = nonce,
            .expected_digest = *digest,
            .independently_reproduced = true,
            .public_provenance = fields[6],
            .source_revision = fields[7],
            .source_tree_fingerprint = fields[8],
            .harness_sha256 = fields[9],
        });
    }
    return manifest;
}

const std::vector<RCProductionGoldenManifestEntry>&
CommittedRCProductionGoldenManifest()
{
    // The input is embedded as numeric byte literals by CMake. Only that inert
    // data file is excluded from the implementation fingerprint; this parser,
    // its schema, the generated-byte conversion, and every qualification rule
    // remain covered. A malformed or code-like seal therefore fails closed as
    // an empty manifest rather than becoming executable input.
    static const std::vector<RCProductionGoldenManifestEntry> manifest{
        ParseRCProductionGoldenManifestData(std::string_view{
            reinterpret_cast<const char*>(kRCProductionGoldenManifestData),
            sizeof(kRCProductionGoldenManifestData) - 1})};
    return manifest;
}

} // namespace matmul::v4::rc
