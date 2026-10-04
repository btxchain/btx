// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/compute_profile.h>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <cstring>

namespace pwc {
namespace {

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

void PutStr(std::vector<unsigned char>& out, std::string_view s)
{
    PutU32(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

WorkProfile MakeProduction()
{
    WorkProfile p;
    p.profile_name = kProductionProfileName;
    p.test_only = false;
    p.rc_profile = 1;
    p.params = matmul::v4::rc::MakeProductionRCEpisodeParams();
    p.mx_block = matmul::v4::rc::kRCMxBlockLen;
    p.seg_len = matmul::v4::rc::kRCSegLen;
    p.segment_leaves = matmul::v4::rc::kRCSegmentLeavesEnabled;
    p.growth_schedule = matmul::v4::rc::kRCGrowthScheduleEnabled;
    p.transcript_version = matmul::v4::rc::kRCTranscriptVersion;
    p.mx_operand_abs_max = static_cast<uint32_t>(matmul::v4::rc::kRCMxOperandAbsMax);
    p.id = ProfileId(p);
    return p;
}

WorkProfile MakeToy()
{
    WorkProfile p;
    p.profile_name = kToyProfileName;
    p.test_only = true;
    p.rc_profile = 1;
    p.params = matmul::v4::rc::MakeToyRCEpisodeParams();
    p.mx_block = matmul::v4::rc::kRCMxBlockLen;
    p.seg_len = matmul::v4::rc::kRCSegLen;
    p.segment_leaves = matmul::v4::rc::kRCSegmentLeavesEnabled;
    p.growth_schedule = matmul::v4::rc::kRCGrowthScheduleEnabled;
    p.transcript_version = matmul::v4::rc::kRCTranscriptVersion;
    p.mx_operand_abs_max = static_cast<uint32_t>(matmul::v4::rc::kRCMxOperandAbsMax);
    p.id = ProfileId(p);
    return p;
}

} // namespace

std::vector<unsigned char> CanonicalDescriptor(const WorkProfile& profile)
{
    std::vector<unsigned char> out;
    out.reserve(256);
    const std::string magic = "BTX_COMPUTE_WORK_PROFILE_V1";
    out.insert(out.end(), magic.begin(), magic.end());
    PutU32(out, profile.schema_version);
    PutStr(out, profile.profile_name);
    PutStr(out, profile.workload_family);
    out.push_back(profile.test_only ? 1 : 0);
    PutU32(out, profile.rc_profile);
    PutU32(out, profile.params.rounds);
    PutU32(out, profile.params.d_head);
    PutU32(out, profile.params.n_q);
    PutU32(out, profile.params.n_ctx);
    PutU32(out, profile.params.L_lyr);
    PutU32(out, profile.params.d_model);
    PutU32(out, profile.params.d_ff);
    PutU32(out, profile.params.b_seq);
    PutU32(out, profile.params.T_leaf);
    PutU32(out, profile.mx_block);
    PutU32(out, profile.seg_len);
    out.push_back(profile.segment_leaves ? 1 : 0);
    out.push_back(profile.growth_schedule ? 1 : 0);
    PutU32(out, profile.transcript_version);
    PutStr(out, profile.arithmetic_mode);
    PutU32(out, profile.seed_derivation_version);
    PutU32(out, profile.header_construction_version);
    PutU32(out, profile.digest_version);
    out.push_back(profile.exactness_required ? 1 : 0);
    PutStr(out, profile.unit_name);
    PutU64(out, profile.microunits_per_episode);
    PutU32(out, profile.semantics_version);
    PutU32(out, profile.mx_operand_abs_max);
    PutStr(out, profile.episode_domain);
    return out;
}

std::array<unsigned char, 48> ProfileId(const WorkProfile& profile)
{
    const auto bytes = CanonicalDescriptor(profile);
    std::array<unsigned char, 48> id{};
    CSHA384 hasher;
    hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(id.data());
    return id;
}

std::string ProfileIdHex(const WorkProfile& profile)
{
    return HexStr(profile.id);
}

const WorkProfile& ProductionProfile()
{
    static const WorkProfile profile = MakeProduction();
    return profile;
}

const WorkProfile& ToyProfile()
{
    static const WorkProfile profile = MakeToy();
    return profile;
}

const WorkProfile* FindWorkProfile(std::string_view name_or_id, bool allow_test, std::string& err_code)
{
    const WorkProfile* found = nullptr;
    if (name_or_id == ProductionProfile().profile_name || name_or_id == ProfileIdHex(ProductionProfile())) {
        found = &ProductionProfile();
    } else if (name_or_id == ToyProfile().profile_name || name_or_id == ProfileIdHex(ToyProfile())) {
        found = &ToyProfile();
    }
    if (!found) {
        err_code = "COMPUTE_PROFILE_UNKNOWN";
        return nullptr;
    }
    if (found->test_only && !allow_test) {
        err_code = "COMPUTE_TEST_PROFILE_DISABLED";
        return nullptr;
    }
    return found;
}

UniValue WorkProfileJson(const WorkProfile& profile)
{
    const auto& p = profile.params;
    UniValue o(UniValue::VOBJ);
    o.pushKV("kind", profile.kind);
    o.pushKV("schema_version", static_cast<int64_t>(profile.schema_version));
    o.pushKV("profile_name", profile.profile_name);
    o.pushKV("profile_id", ProfileIdHex(profile));
    o.pushKV("workload_family", profile.workload_family);
    o.pushKV("test_only", profile.test_only);
    o.pushKV("rc_profile", static_cast<int64_t>(profile.rc_profile));
    o.pushKV("rounds", static_cast<int64_t>(p.rounds));
    o.pushKV("d_head", static_cast<int64_t>(p.d_head));
    o.pushKV("n_q", static_cast<int64_t>(p.n_q));
    o.pushKV("n_ctx", static_cast<int64_t>(p.n_ctx));
    o.pushKV("L_lyr", static_cast<int64_t>(p.L_lyr));
    o.pushKV("d_model", static_cast<int64_t>(p.d_model));
    o.pushKV("d_ff", static_cast<int64_t>(p.d_ff));
    o.pushKV("b_seq", static_cast<int64_t>(p.b_seq));
    o.pushKV("T_leaf", static_cast<int64_t>(p.T_leaf));
    o.pushKV("mx_block", static_cast<int64_t>(profile.mx_block));
    o.pushKV("seg_len", static_cast<int64_t>(profile.seg_len));
    o.pushKV("segment_leaves", profile.segment_leaves);
    o.pushKV("growth_schedule", profile.growth_schedule);
    o.pushKV("transcript_version", static_cast<int64_t>(profile.transcript_version));
    o.pushKV("arithmetic_mode", profile.arithmetic_mode);
    o.pushKV("seed_derivation_version", static_cast<int64_t>(profile.seed_derivation_version));
    o.pushKV("header_construction_version", static_cast<int64_t>(profile.header_construction_version));
    o.pushKV("digest_version", static_cast<int64_t>(profile.digest_version));
    o.pushKV("exactness_required", profile.exactness_required);
    o.pushKV("unit_name", profile.unit_name);
    o.pushKV("microunits_per_episode", profile.microunits_per_episode);
    o.pushKV("semantics_version", static_cast<int64_t>(profile.semantics_version));
    o.pushKV("mx_operand_abs_max", static_cast<int64_t>(profile.mx_operand_abs_max));
    o.pushKV("episode_domain", profile.episode_domain);
    return o;
}

UniValue ListWorkProfilesJson(bool allow_test)
{
    UniValue arr(UniValue::VARR);
    arr.push_back(WorkProfileJson(ProductionProfile()));
    if (allow_test) arr.push_back(WorkProfileJson(ToyProfile()));
    UniValue o(UniValue::VOBJ);
    o.pushKV("profiles", arr);
    o.pushKV("test_profiles_enabled", allow_test);
    o.pushKV("unit_name", "P1E");
    o.pushKV("microunits_per_episode", P1E_MICROUNITS);
    return o;
}

} // namespace pwc
