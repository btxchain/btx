// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_relay_fixture_builder.h>

#include <chainparams.h>
#include <common/args.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

struct ParsedArgs
{
    btx::test::shielded::RelayFixtureFamily family{
        btx::test::shielded::RelayFixtureFamily::REBALANCE};
    COutPoint funding_outpoint;
    CAmount funding_value{0};
    CScript change_script;
    CAmount fee{40'000};
    int32_t validation_height{std::numeric_limits<int32_t>::max()};
    std::optional<int32_t> regtest_matrict_disable_height;
};

btx::test::shielded::RelayFixtureFamily ParseFamily(std::string_view value)
{
    if (value == "rebalance") {
        return btx::test::shielded::RelayFixtureFamily::REBALANCE;
    }
    if (value == "settlement_anchor_receipt" || value == "reserve_bound_settlement_anchor_receipt") {
        return btx::test::shielded::RelayFixtureFamily::RESERVE_BOUND_SETTLEMENT_ANCHOR_RECEIPT;
    }
    if (value == "egress_receipt") {
        return btx::test::shielded::RelayFixtureFamily::EGRESS_RECEIPT;
    }
    throw std::runtime_error("unsupported family: " + std::string{value});
}

uint32_t ParseVout(std::string_view value)
{
    return static_cast<uint32_t>(std::stoul(std::string{value}));
}

CAmount ParseAmount(std::string_view value, std::string_view option_name)
{
    const long long parsed = std::stoll(std::string{value});
    if (parsed <= 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return parsed;
}

int32_t ParseValidationHeight(std::string_view value)
{
    const long long parsed = std::stoll(std::string{value});
    if (parsed < 0 || parsed > std::numeric_limits<int32_t>::max()) {
        throw std::runtime_error("invalid --validation-height");
    }
    return static_cast<int32_t>(parsed);
}

int32_t ParseNonNegativeInt32(std::string_view value, std::string_view option_name)
{
    const long long parsed = std::stoll(std::string{value});
    if (parsed < 0 || parsed > std::numeric_limits<int32_t>::max()) {
        throw std::runtime_error(std::string{option_name} + " must be a non-negative int32");
    }
    return static_cast<int32_t>(parsed);
}

ParsedArgs ParseArgs(int argc, char** argv, fs::path& output_path)
{
    ParsedArgs parsed;
    bool saw_txid{false};
    bool saw_vout{false};
    bool saw_value{false};
    bool saw_change_script{false};
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_relay_fixture_tx "
                         "--family=rebalance|settlement_anchor_receipt|egress_receipt "
                         "--input-txid=<hex> --input-vout=<n> --input-value-sats=<sats> "
                         "--change-script=<hex> [--fee-sats=<sats>] [--validation-height=<n>] "
                         "[--regtestshieldedmatrictdisableheight=<n>] "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--family=")) {
            parsed.family = ParseFamily(arg.substr(9));
            continue;
        }
        if (arg.starts_with("--input-txid=")) {
            std::optional<uint256> hash = uint256::FromHex(std::string{arg.substr(13)});
            if (!hash.has_value()) {
                throw std::runtime_error("invalid --input-txid");
            }
            parsed.funding_outpoint.hash = Txid::FromUint256(*hash);
            saw_txid = true;
            continue;
        }
        if (arg.starts_with("--input-vout=")) {
            parsed.funding_outpoint.n = ParseVout(arg.substr(13));
            saw_vout = true;
            continue;
        }
        if (arg.starts_with("--input-value-sats=")) {
            parsed.funding_value = ParseAmount(arg.substr(19), "--input-value-sats");
            saw_value = true;
            continue;
        }
        if (arg.starts_with("--change-script=")) {
            const auto bytes = ParseHex(std::string{arg.substr(16)});
            if (bytes.empty()) {
                throw std::runtime_error("invalid --change-script");
            }
            parsed.change_script = CScript(bytes.begin(), bytes.end());
            saw_change_script = true;
            continue;
        }
        if (arg.starts_with("--fee-sats=")) {
            parsed.fee = ParseAmount(arg.substr(11), "--fee-sats");
            continue;
        }
        if (arg.starts_with("--validation-height=")) {
            parsed.validation_height = ParseValidationHeight(arg.substr(20));
            continue;
        }
        if (arg.starts_with("--regtestshieldedmatrictdisableheight=")) {
            parsed.regtest_matrict_disable_height =
                ParseNonNegativeInt32(arg.substr(38), "--regtestshieldedmatrictdisableheight");
            continue;
        }
        if (arg.starts_with("--output=")) {
            output_path = fs::PathFromString(std::string{arg.substr(9)});
            continue;
        }
        throw std::runtime_error("unknown argument: " + std::string{arg});
    }
    const bool needs_fee_carrier = parsed.family != btx::test::shielded::RelayFixtureFamily::EGRESS_RECEIPT;
    if (needs_fee_carrier && (!saw_txid || !saw_vout || !saw_value || !saw_change_script)) {
        throw std::runtime_error("missing required input arguments");
    }
    return parsed;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        SelectParams(ChainType::REGTEST);
        fs::path output_path;
        const ParsedArgs args = ParseArgs(argc, argv, output_path);
        std::unique_ptr<const CChainParams> custom_chain_params;
        const Consensus::Params* effective_consensus = nullptr;
        if (args.regtest_matrict_disable_height.has_value()) {
            ArgsManager chain_args;
            chain_args.ForceSetArg(
                "-regtestshieldedmatrictdisableheight",
                std::to_string(*args.regtest_matrict_disable_height));
            custom_chain_params = CreateChainParams(chain_args, ChainType::REGTEST);
            effective_consensus = &custom_chain_params->GetConsensus();
        }

        std::string reject_reason;
        const auto built = btx::test::shielded::BuildRelayFixtureTransaction(
            args.family,
            {
                .funding_outpoint = args.funding_outpoint,
                .funding_value = args.funding_value,
                .change_script = args.change_script,
                .fee = args.fee,
            },
            reject_reason,
            args.validation_height,
            effective_consensus);
        if (!built.has_value()) {
            throw std::runtime_error(
                reject_reason.empty() ? "failed to build relay fixture transaction" : reject_reason);
        }

        UniValue out(UniValue::VOBJ);
        out.pushKV("family", built->family_name);
        out.pushKV("tx_hex", EncodeHexTx(CTransaction{built->tx}));
        if (built->netting_manifest_id.has_value()) {
            out.pushKV("netting_manifest_id", built->netting_manifest_id->GetHex());
        }
        if (built->settlement_anchor_digest.has_value()) {
            out.pushKV("settlement_anchor_digest", built->settlement_anchor_digest->GetHex());
        }

        const std::string json = out.write(2) + '\n';
        if (output_path.empty()) {
            std::cout << json;
        } else {
            std::ofstream output{output_path};
            if (!output.is_open()) {
                throw std::runtime_error("unable to open output path");
            }
            output << json;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "gen_shielded_relay_fixture_tx: " << e.what() << '\n';
        return 1;
    }
}
