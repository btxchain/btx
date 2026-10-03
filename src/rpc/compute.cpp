// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>

#include <chain.h>
#include <cstring>
#include <util/fs.h>
#include <common/args.h>
#include <matmul/compute_passport.h>
#include <matmul/compute_profile.h>
#include <matmul/compute_qualification.h>
#include <node/context.h>
#include <random.h>
#include <sync.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <validation.h>

#include <chrono>
#include <memory>
#include <string>

using node::NodeContext;

namespace {

bool TestProfilesEnabled()
{
    if (gArgs.GetChainType() != ChainType::REGTEST) return false;
    return gArgs.GetBoolArg("-enablecomputetestprofiles", false);
}

bool ProductionWorkEnabled()
{
    return gArgs.GetBoolArg("-enablecomputeproductionwork", false);
}

int64_t NowMs()
{
    return GetTime<std::chrono::milliseconds>().count();
}

fs::path QualificationPath()
{
    const std::string arg = gArgs.GetArg("-computequalificationfile", "");
    if (!arg.empty()) {
        const fs::path given = fs::PathFromString(arg);
        if (given.is_relative()) return gArgs.GetDataDirNet() / given;
        return given;
    }
    return gArgs.GetDataDirNet() / "compute_qualifications.dat";
}

class RegistryHolder {
public:
    pwc::QualificationRegistry& Get(std::string& err)
    {
        LOCK(m_mu);
        if (!m_opened) {
            m_opened = true;
            m_registry.Open(QualificationPath(), err);
        }
        return m_registry;
    }

private:
    Mutex m_mu;
    bool m_opened{false};
    pwc::QualificationRegistry m_registry;
};

RegistryHolder& Registry()
{
    static RegistryHolder holder;
    return holder;
}

void ThrowCode(const std::string& code, const std::string& err)
{
    throw JSONRPCError(RPC_INVALID_PARAMETER, code + (err.empty() ? "" : ": " + err));
}

RPCHelpMan getcomputeworkprofiles()
{
    return RPCHelpMan{
        "getcomputeworkprofiles",
        "List Pay With Compute work profiles. The toy profile is regtest-only.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ARR, "profiles", "", {{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}}}},
            {RPCResult::Type::BOOL, "test_profiles_enabled", ""},
            {RPCResult::Type::STR, "unit_name", ""},
            {RPCResult::Type::NUM, "microunits_per_episode", ""},
        }},
        RPCExamples{HelpExampleCli("getcomputeworkprofiles", "")},
        [](const RPCHelpMan&, const JSONRPCRequest&) -> UniValue {
            return pwc::ListWorkProfilesJson(TestProfilesEnabled());
        },
    };
}

RPCHelpMan getcomputeworkprofile()
{
    return RPCHelpMan{
        "getcomputeworkprofile",
        "Return one frozen compute work profile by name or profile id.\n",
        {{"profile", RPCArg::Type::STR, RPCArg::Optional::NO, "Profile name or profile id"}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("getcomputeworkprofile", "btx-rc-p1e-v1")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            std::string code;
            const pwc::WorkProfile* profile = pwc::FindWorkProfile(request.params[0].get_str(), TestProfilesEnabled(), code);
            if (!profile) ThrowCode(code, "profile");
            return pwc::WorkProfileJson(*profile);
        },
    };
}

RPCHelpMan issuecomputequalification()
{
    return RPCHelpMan{
        "issuecomputequalification",
        "Issue a fresh exact-replay compute qualification challenge. This is not chainwork.\n",
        {
            {"subject", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte subject digest hex"},
            {"profile", RPCArg::Type::STR, RPCArg::Optional::NO, "Work profile name or id"},
            {"episode_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Episodes, 1 to 16"},
            {"expires_in_s", RPCArg::Type::NUM, RPCArg::Optional::NO, "Challenge lifetime in seconds"},
            {"max_elapsed_ms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional issuer elapsed ceiling"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("issuecomputequalification", "\"<subject>\" \"btx-rc-p1e-toy-v1\" 1 300")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const std::string subject_hex = request.params[0].get_str();
            auto subject = ParseHex(subject_hex);
            if (subject.size() != 32) ThrowCode("COMPUTE_SUBJECT_MISMATCH", "subject must be 32 bytes");
            pwc::QualificationFreshness in;
            in.network = ChainTypeToString(gArgs.GetChainType());
            in.profile_name = request.params[1].get_str();
            std::memcpy(in.subject.data(), subject.data(), 32);
            GetStrongRandBytes(in.issuer_nonce);
            in.episode_count = static_cast<uint32_t>(request.params[2].getInt<int64_t>());
            const int64_t expires = request.params[3].getInt<int64_t>();
            if (expires < 1 || expires > 86400) ThrowCode("COMPUTE_CHALLENGE_INVALID", "expires_in_s");
            in.issued_at_ms = NowMs();
            in.expires_at_ms = in.issued_at_ms + expires * 1000;
            if (!request.params[4].isNull()) in.max_elapsed_ms = request.params[4].getInt<uint64_t>();
            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            if (const CBlockIndex* tip = chainman.ActiveChain().Tip()) {
                in.anchor_height = tip->nHeight;
                in.anchor_hash = tip->GetBlockHash();
            }
            UniValue challenge;
            std::string code, err;
            if (!pwc::IssueQualification(in, TestProfilesEnabled(), challenge, code, err)) ThrowCode(code, err);
            std::string reg_err;
            auto& reg = Registry().Get(reg_err);
            if (!reg.RememberIssued(challenge, code, err)) ThrowCode(code.empty() ? "COMPUTE_CHALLENGE_INVALID" : code, err.empty() ? reg_err : err);
            return challenge;
        },
    };
}

RPCHelpMan solvecomputequalification()
{
    return RPCHelpMan{
        "solvecomputequalification",
        "Solve a compute qualification locally with exact Profile-1 replay. Client timing is advisory.\n",
        {
            {"challenge", RPCArg::Type::STR, RPCArg::Optional::NO, "Challenge object", RPCArgOptions{.skip_type_check = true}},
            {"backend", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Advisory label. Verification always recomputes exactly."},
            {"time_budget_ms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Stop before the next episode once this budget is exceeded"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("solvecomputequalification", "'{\"kind\":\"btx_compute_qualification_v1\"}'")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            uint64_t budget = 0;
            if (!request.params[2].isNull()) budget = request.params[2].getInt<uint64_t>();
            UniValue response;
            std::string code, err;
            if (!pwc::SolveQualification(request.params[0], budget, ProductionWorkEnabled(), response, code, err)) {
                ThrowCode(code, err);
            }
            if (!request.params[1].isNull() && response.exists("solver_telemetry")) {
                UniValue telemetry = response["solver_telemetry"];
                telemetry.pushKV("backend_requested", request.params[1].get_str());
                response.pushKV("solver_telemetry", telemetry);
            }
            return response;
        },
    };
}

RPCHelpMan verifycomputequalification()
{
    return RPCHelpMan{
        "verifycomputequalification",
        "Recompute a qualification without consuming it.\n",
        {
            {"challenge", RPCArg::Type::STR, RPCArg::Optional::NO, "Issued challenge", RPCArgOptions{.skip_type_check = true}},
            {"response", RPCArg::Type::STR, RPCArg::Optional::NO, "Solver response", RPCArgOptions{.skip_type_check = true}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("verifycomputequalification", "'{}' '{}'")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            std::string code, err, reg_err;
            UniValue out;
            auto& reg = Registry().Get(reg_err);
            if (!reg.Verify(request.params[0], request.params[1], /*redeem=*/false, NowMs(), out, code, err)) {
                ThrowCode(code, err.empty() ? reg_err : err);
            }
            return out;
        },
    };
}

RPCHelpMan redeemcomputequalification()
{
    return RPCHelpMan{
        "redeemcomputequalification",
        "Verify a qualification and mark it redeemed. A second redemption fails.\n",
        {
            {"challenge", RPCArg::Type::STR, RPCArg::Optional::NO, "Issued challenge", RPCArgOptions{.skip_type_check = true}},
            {"response", RPCArg::Type::STR, RPCArg::Optional::NO, "Solver response", RPCArgOptions{.skip_type_check = true}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("redeemcomputequalification", "'{}' '{}'")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            std::string code, err, reg_err;
            UniValue out;
            auto& reg = Registry().Get(reg_err);
            if (!reg.Verify(request.params[0], request.params[1], /*redeem=*/true, NowMs(), out, code, err)) {
                ThrowCode(code, err.empty() ? reg_err : err);
            }
            return out;
        },
    };
}

RPCHelpMan getcomputequalificationstatus()
{
    return RPCHelpMan{
        "getcomputequalificationstatus",
        "Return issued, expired, redeemed, or unknown for a challenge id.\n",
        {{"challenge_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Challenge id hex"}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("getcomputequalificationstatus", "\"<id>\"")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            std::string code, err, reg_err;
            UniValue out;
            auto& reg = Registry().Get(reg_err);
            if (!reg.Status(request.params[0].get_str(), NowMs(), out, code, err)) ThrowCode(code, err.empty() ? reg_err : err);
            return out;
        },
    };
}

RPCHelpMan getcomputestatus()
{
    return RPCHelpMan{
        "getcomputestatus",
        "Qualification registry health. No wallet or monetary fields.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("getcomputestatus", "")},
        [](const RPCHelpMan&, const JSONRPCRequest&) -> UniValue {
            std::string reg_err;
            auto& reg = Registry().Get(reg_err);
            UniValue out = reg.Health();
            out.pushKV("test_profiles_enabled", TestProfilesEnabled());
            out.pushKV("production_work_enabled", ProductionWorkEnabled());
            out.pushKV("profiles", pwc::ListWorkProfilesJson(TestProfilesEnabled())["profiles"]);
            if (!reg_err.empty() && !out.exists("error")) out.pushKV("error", reg_err);
            return out;
        },
    };
}

RPCHelpMan buildcomputepassport()
{
    return RPCHelpMan{
        "buildcomputepassport",
        "Build a self-attested Compute Passport from integer microsecond samples. Not a qualification.\n",
        {{"samples", RPCArg::Type::STR, RPCArg::Optional::NO, "profile_name and wall_us[]", RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
        RPCExamples{HelpExampleCli("buildcomputepassport", "'{\"profile_name\":\"btx-rc-p1e-toy-v1\",\"wall_us\":[1000]}'")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const UniValue& in = request.params[0];
            if (!in.isObject() || !in.exists("profile_name") || !in.exists("wall_us") || !in["wall_us"].isArray()) {
                ThrowCode("COMPUTE_RECORD_INVALID", "samples");
            }
            if (!TestProfilesEnabled()) {
                std::string code;
                if (!pwc::FindWorkProfile(in["profile_name"].get_str(), false, code)) ThrowCode(code, "profile");
            }
            pwc::PassportSamples samples;
            samples.profile_name = in["profile_name"].get_str();
            for (const auto& v : in["wall_us"].getValues()) samples.wall_us.push_back(v.getInt<uint64_t>());
            samples.generated_at_ms = in.exists("generated_at_ms") ? in["generated_at_ms"].getInt<int64_t>() : NowMs();
            auto str = [&](const char* k) { return in.exists(k) && in[k].isStr() ? in[k].get_str() : std::string{}; };
            samples.backend_requested = str("backend_requested");
            samples.backend_resolved = str("backend_resolved");
            samples.embedded_source_revision = str("embedded_source_revision");
            samples.source_tree_fingerprint = str("source_tree_fingerprint");
            samples.raw_report_digest = str("raw_report_digest");
            samples.provider_family = str("provider_family");
            samples.device_architecture = str("device_architecture");
            samples.runtime_identity = str("runtime_identity");
            samples.driver_identity = str("driver_identity");
            if (in.exists("embedded_source_dirty")) samples.embedded_source_dirty = in["embedded_source_dirty"].get_bool();
            if (in.exists("all_fully_accelerated")) samples.all_fully_accelerated = in["all_fully_accelerated"].get_bool();
            if (in.exists("cpu_fallbacks")) samples.cpu_fallbacks = in["cpu_fallbacks"].getInt<uint64_t>();
            UniValue out;
            std::string err;
            if (!pwc::BuildPassport(samples, out, err)) ThrowCode(err, "passport");
            return out;
        },
    };
}

} // namespace

void RegisterComputeRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &getcomputeworkprofiles},
        {"mining", &getcomputeworkprofile},
        {"mining", &issuecomputequalification},
        {"mining", &solvecomputequalification},
        {"mining", &verifycomputequalification},
        {"mining", &redeemcomputequalification},
        {"mining", &getcomputequalificationstatus},
        {"mining", &getcomputestatus},
        {"mining", &buildcomputepassport},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
