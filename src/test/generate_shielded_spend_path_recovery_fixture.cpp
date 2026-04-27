// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_spend_path_recovery_fixture_builder.h>

#include <core_io.h>
#include <primitives/transaction.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using btx::test::shielded::SpendPathRecoveryFixtureBuildInput;
using btx::test::shielded::SpendPathRecoveryFundingInput;

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

SpendPathRecoveryFixtureBuildInput ParseArgs(int argc, char** argv, fs::path& output_path)
{
    SpendPathRecoveryFixtureBuildInput parsed;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_spend_path_recovery_fixture "
                         "--legacy-input=<txid>:<vout>:<value_sats> "
                         "[--legacy-fee-sats=<sats>] [--recovery-fee-sats=<sats>] "
                         "[--validation-height=<height>] "
                         "[--matrict-disable-height=<height>] "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--legacy-input=")) {
            const std::string value{arg.substr(15)};
            const auto first = value.find(':');
            const auto second = value.find(':', first == std::string::npos ? first : first + 1);
            if (first == std::string::npos || second == std::string::npos) {
                throw std::runtime_error("invalid --legacy-input");
            }
            const auto txid_hex = value.substr(0, first);
            const auto vout_str = value.substr(first + 1, second - first - 1);
            const auto amount_str = value.substr(second + 1);
            auto hash = uint256::FromHex(txid_hex);
            if (!hash.has_value()) {
                throw std::runtime_error("invalid --legacy-input txid");
            }
            parsed.legacy_funding_inputs.push_back(SpendPathRecoveryFundingInput{
                .funding_outpoint = COutPoint{Txid::FromUint256(*hash), ParseVout(vout_str)},
                .funding_value = ParseAmount(amount_str, "--legacy-input"),
            });
            continue;
        }
        if (arg.starts_with("--legacy-fee-sats=")) {
            parsed.legacy_shield_fee = ParseAmount(arg.substr(18), "--legacy-fee-sats");
            continue;
        }
        if (arg.starts_with("--recovery-fee-sats=")) {
            parsed.recovery_fee = ParseAmount(arg.substr(20), "--recovery-fee-sats");
            continue;
        }
        if (arg.starts_with("--validation-height=")) {
            const long parsed_height = std::stol(std::string{arg.substr(20)});
            if (parsed_height <= 0) {
                throw std::runtime_error("--validation-height must be greater than zero");
            }
            parsed.validation_height = static_cast<int32_t>(parsed_height);
            continue;
        }
        if (arg.starts_with("--matrict-disable-height=")) {
            const long parsed_height = std::stol(std::string{arg.substr(25)});
            if (parsed_height <= 0) {
                throw std::runtime_error("--matrict-disable-height must be greater than zero");
            }
            parsed.matrict_disable_height = static_cast<int32_t>(parsed_height);
            continue;
        }
        if (arg.starts_with("--output=")) {
            output_path = fs::PathFromString(std::string{arg.substr(9)});
            continue;
        }
        throw std::runtime_error("unknown argument: " + std::string{arg});
    }
    return parsed;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        fs::path output_path;
        const auto parsed = ParseArgs(argc, argv, output_path);

        std::string reject_reason;
        const auto built =
            btx::test::shielded::BuildSpendPathRecoveryFixture(parsed, reject_reason);
        if (!built.has_value()) {
            throw std::runtime_error(reject_reason.empty()
                                         ? "failed to build spend-path recovery fixture"
                                         : reject_reason);
        }

        UniValue out(UniValue::VOBJ);
        out.pushKV("validation_height", parsed.validation_height);
        out.pushKV("matrict_disable_height", parsed.matrict_disable_height);
        out.pushKV("legacy_anchor", built->legacy_anchor.GetHex());
        out.pushKV("recovery_anchor", built->recovery_anchor.GetHex());
        out.pushKV("recovery_input_note_commitment", built->recovery_input_note_commitment.GetHex());
        out.pushKV("recovery_output_note_commitment", built->recovery_output_note_commitment.GetHex());
        out.pushKV("recovery_tx_hex", EncodeHexTx(CTransaction{built->recovery_tx}));
        out.pushKV("recovery_txid", built->recovery_tx.GetHash().GetHex());

        UniValue legacy_txs(UniValue::VARR);
        for (size_t i = 0; i < built->legacy_txs.size(); ++i) {
            UniValue tx(UniValue::VOBJ);
            tx.pushKV("tx_hex", EncodeHexTx(CTransaction{built->legacy_txs[i]}));
            tx.pushKV("note_commitment", built->legacy_note_commitments[i].GetHex());
            legacy_txs.push_back(std::move(tx));
        }
        out.pushKV("legacy_txs", std::move(legacy_txs));

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
        std::cerr << "gen_shielded_spend_path_recovery_fixture: " << e.what() << '\n';
        return 1;
    }
}
