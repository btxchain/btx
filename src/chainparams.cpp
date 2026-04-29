// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using util::SplitString;

namespace {

std::optional<std::vector<uint8_t>> ParseFixedHex(std::string_view value, size_t expected_size)
{
    const auto no_prefix = util::RemovePrefixView(util::RemovePrefixView(value, "0x"), "0X");
    const auto parsed = TryParseHex<uint8_t>(no_prefix);
    if (!parsed || parsed->size() != expected_size) return std::nullopt;
    return parsed;
}

uint32_t ParseHexU32(const std::string& arg_name, std::string_view value)
{
    const auto parsed = ParseFixedHex(value, 4);
    if (!parsed) {
        throw std::runtime_error(strprintf("Invalid %s value (%s): expected 8 hex chars.", arg_name, value));
    }
    return (uint32_t{(*parsed)[0]} << 24) |
           (uint32_t{(*parsed)[1]} << 16) |
           (uint32_t{(*parsed)[2]} << 8) |
            uint32_t{(*parsed)[3]};
}

int32_t ParseRegTestNonNegativeInt32Arg(const ArgsManager& args, const std::string& arg_name)
{
    const auto raw = args.GetArg(arg_name, "");
    int32_t value{0};
    if (!ParseInt32(raw, &value) || value < 0) {
        throw std::runtime_error(strprintf("Invalid %s value (%s): expected non-negative int32.", arg_name, raw));
    }
    return value;
}

int64_t ParseRegTestPositiveInt64Arg(const ArgsManager& args, const std::string& arg_name)
{
    const auto raw = args.GetArg(arg_name, "");
    int64_t value{0};
    if (!ParseInt64(raw, &value) || value <= 0) {
        throw std::runtime_error(strprintf("Invalid %s value (%s): expected positive int64.", arg_name, raw));
    }
    return value;
}

uint32_t ParseRegTestUInt32Arg(const ArgsManager& args, const std::string& arg_name)
{
    const auto raw = args.GetArg(arg_name, "");
    uint32_t value{0};
    if (!ParseUInt32(raw, &value)) {
        throw std::runtime_error(strprintf("Invalid %s value (%s): expected uint32.", arg_name, raw));
    }
    return value;
}

bool ParseRegTestBoolArg(const ArgsManager& args, const std::string& arg_name)
{
    const std::string raw = ToLower(args.GetArg(arg_name, ""));
    if (raw == "1" || raw == "true") return true;
    if (raw == "0" || raw == "false") return false;
    throw std::runtime_error(strprintf("Invalid %s value (%s): expected 0, 1, true, or false.", arg_name, raw));
}

} // namespace

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (!args.GetArgs("-signetseednode").empty()) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (!args.GetArgs("-signetchallenge").empty()) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
    if (const auto signetblocktime{args.GetIntArg("-signetblocktime")}) {
        if (!args.IsArgSet("-signetchallenge")) {
            throw std::runtime_error("-signetblocktime cannot be set without -signetchallenge");
        }
        if (*signetblocktime <= 0) {
            throw std::runtime_error("-signetblocktime must be greater than 0");
        }
        options.pow_target_spacing = *signetblocktime;
    }
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;
    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;
    if (HasTestOption(args, "matmulstrict") || HasTestOption(args, "kawpowstrict")) options.matmul_strict = true;
    if (HasTestOption(args, "matmuldgw")) options.matmul_dgw = true;

    if (args.IsArgSet("-regtestmsgstart")) {
        const auto raw = args.GetArg("-regtestmsgstart", "");
        const auto parsed = ParseFixedHex(raw, 4);
        if (!parsed) {
            throw std::runtime_error(strprintf("Invalid -regtestmsgstart value (%s): expected 8 hex chars.", raw));
        }
        options.message_start = MessageStartChars{(*parsed)[0], (*parsed)[1], (*parsed)[2], (*parsed)[3]};
    }

    if (args.IsArgSet("-regtestport")) {
        const auto raw = args.GetArg("-regtestport", "");
        uint16_t port{0};
        if (!ParseUInt16(raw, &port) || port == 0) {
            throw std::runtime_error(strprintf("Invalid -regtestport value (%s): expected integer in [1,65535].", raw));
        }
        options.default_port = port;
    }

    if (args.IsArgSet("-regtestgenesisntime")) {
        const auto raw = args.GetArg("-regtestgenesisntime", "");
        uint32_t ntime{0};
        if (!ParseUInt32(raw, &ntime)) {
            throw std::runtime_error(strprintf("Invalid -regtestgenesisntime value (%s): expected uint32 decimal.", raw));
        }
        options.genesis_time = ntime;
    }

    if (args.IsArgSet("-regtestgenesisnonce")) {
        const auto raw = args.GetArg("-regtestgenesisnonce", "");
        uint32_t nonce{0};
        if (!ParseUInt32(raw, &nonce)) {
            throw std::runtime_error(strprintf("Invalid -regtestgenesisnonce value (%s): expected uint32 decimal.", raw));
        }
        options.genesis_nonce = nonce;
    }

    if (args.IsArgSet("-regtestgenesisbits")) {
        const auto raw = args.GetArg("-regtestgenesisbits", "");
        options.genesis_bits = ParseHexU32("-regtestgenesisbits", raw);
    }

    if (args.IsArgSet("-regtestgenesisversion")) {
        const auto raw = args.GetArg("-regtestgenesisversion", "");
        int32_t version{0};
        if (!ParseInt32(raw, &version)) {
            throw std::runtime_error(strprintf("Invalid -regtestgenesisversion value (%s): expected int32 decimal.", raw));
        }
        options.genesis_version = version;
    }

    if (args.IsArgSet("-mldsadisableheight")) {
        const auto raw = args.GetArg("-mldsadisableheight", "");
        int32_t height{0};
        if (!ParseInt32(raw, &height) || height < 0) {
            throw std::runtime_error(strprintf("Invalid -mldsadisableheight value (%s): expected non-negative int32.", raw));
        }
        options.mldsa_disable_height = height;
    }
    if (args.IsArgSet("-regtestshieldedtxbindingactivationheight")) {
        options.shielded_tx_binding_activation_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestshieldedtxbindingactivationheight");
    }
    if (args.IsArgSet("-regtestshieldedbridgetagactivationheight")) {
        options.shielded_bridge_tag_activation_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestshieldedbridgetagactivationheight");
    }
    if (args.IsArgSet("-regtestshieldedsmilericecodecdisableheight")) {
        options.shielded_smile_rice_codec_disable_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestshieldedsmilericecodecdisableheight");
    }
    if (args.IsArgSet("-regtestshieldedmatrictdisableheight")) {
        options.shielded_matrict_disable_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestshieldedmatrictdisableheight");
    }
    if (args.IsArgSet("-regtestshieldedspendpathrecoveryactivationheight")) {
        options.shielded_spend_path_recovery_activation_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestshieldedspendpathrecoveryactivationheight");
    }
    if (args.IsArgSet("-regtestshieldedpq128upgradeheight")) {
        options.shielded_pq128_upgrade_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestshieldedpq128upgradeheight");
    }
    if (args.IsArgSet("-regtestmatmulbindingheight")) {
        options.matmul_binding_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestmatmulbindingheight");
    }
    if (args.IsArgSet("-regtestmatmulproductdigestheight")) {
        options.matmul_product_digest_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestmatmulproductdigestheight");
    }
    if (args.IsArgSet("-regtestmatmulrequireproductpayload")) {
        options.matmul_require_product_payload =
            ParseRegTestBoolArg(args, "-regtestmatmulrequireproductpayload");
    }
    if (args.IsArgSet("-regtestmatmulaserthalflife")) {
        options.matmul_asert_half_life =
            ParseRegTestPositiveInt64Arg(args, "-regtestmatmulaserthalflife");
    }
    if (args.IsArgSet("-regtestmatmulaserthalflifeupgradeheight")) {
        options.matmul_asert_half_life_upgrade_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestmatmulaserthalflifeupgradeheight");
    }
    if (args.IsArgSet("-regtestmatmulaserthalflifeupgrade")) {
        options.matmul_asert_half_life_upgrade =
            ParseRegTestPositiveInt64Arg(args, "-regtestmatmulaserthalflifeupgrade");
    }
    if (options.matmul_asert_half_life_upgrade_height.has_value() !=
        options.matmul_asert_half_life_upgrade.has_value()) {
        throw std::runtime_error(
            "Both -regtestmatmulaserthalflifeupgradeheight and "
            "-regtestmatmulaserthalflifeupgrade must be set together.");
    }
    if (args.IsArgSet("-regtestmatmulprehashepsilonbitsupgradeheight")) {
        options.matmul_pre_hash_epsilon_bits_upgrade_height =
            ParseRegTestNonNegativeInt32Arg(args, "-regtestmatmulprehashepsilonbitsupgradeheight");
    }
    if (args.IsArgSet("-regtestmatmulprehashepsilonbitsupgrade")) {
        options.matmul_pre_hash_epsilon_bits_upgrade =
            ParseRegTestUInt32Arg(args, "-regtestmatmulprehashepsilonbitsupgrade");
    }
    if (options.matmul_pre_hash_epsilon_bits_upgrade_height.has_value() !=
        options.matmul_pre_hash_epsilon_bits_upgrade.has_value()) {
        throw std::runtime_error(
            "Both -regtestmatmulprehashepsilonbitsupgradeheight and "
            "-regtestmatmulprehashepsilonbitsupgrade must be set together.");
    }

    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return CChainParams::Main();
    case ChainType::TESTNET:
        return CChainParams::TestNet();
    case ChainType::TESTNET4:
        return CChainParams::TestNet4();
    case ChainType::SHIELDEDV2DEV:
        return CChainParams::ShieldedV2Dev();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}
