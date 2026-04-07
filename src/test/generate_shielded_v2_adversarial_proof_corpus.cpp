// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_adversarial_proof_corpus.h>

#include <univalue.h>
#include <util/fs.h>

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

struct ParsedArgs
{
    std::string base_tx_hex;
    fs::path base_tx_file;
};

ParsedArgs ParseArgs(int argc, char** argv, fs::path& output_path)
{
    ParsedArgs parsed;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help") {
            std::cout << "Usage: gen_shielded_v2_adversarial_proof_corpus "
                         "(--base-tx-hex=<hex> | --base-tx-file=/path/base.tx.hex) "
                         "[--output=/path/report.json]\n";
            std::exit(0);
        }
        if (arg.starts_with("--base-tx-hex=")) {
            parsed.base_tx_hex = std::string{arg.substr(14)};
            continue;
        }
        if (arg.starts_with("--base-tx-file=")) {
            parsed.base_tx_file = fs::PathFromString(std::string{arg.substr(15)});
            continue;
        }
        if (arg.starts_with("--output=")) {
            output_path = fs::PathFromString(std::string{arg.substr(9)});
            continue;
        }
        throw std::runtime_error("unknown argument: " + std::string{arg});
    }
    if (!parsed.base_tx_hex.empty() && !parsed.base_tx_file.empty()) {
        throw std::runtime_error("specify only one of --base-tx-hex or --base-tx-file");
    }
    if (parsed.base_tx_hex.empty() && !parsed.base_tx_file.empty()) {
        std::ifstream input{parsed.base_tx_file};
        if (!input.is_open()) {
            throw std::runtime_error("unable to open base tx file");
        }
        parsed.base_tx_hex.assign(
            std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{});
        while (!parsed.base_tx_hex.empty() &&
               (parsed.base_tx_hex.back() == '\n' || parsed.base_tx_hex.back() == '\r' ||
                parsed.base_tx_hex.back() == ' ' || parsed.base_tx_hex.back() == '\t')) {
            parsed.base_tx_hex.pop_back();
        }
    }
    if (parsed.base_tx_hex.empty()) {
        throw std::runtime_error("missing required --base-tx-hex or --base-tx-file");
    }
    return parsed;
}

UniValue VariantToUniValue(const btx::test::shielded::AdversarialProofVariant& variant)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("id", variant.id);
    entry.pushKV("description", variant.description);
    entry.pushKV("expected_reject_reason", variant.expected_reject_reason);
    entry.pushKV("expected_failure_stage", variant.expected_failure_stage);
    entry.pushKV("tx_hex", variant.tx_hex);
    entry.pushKV("txid", variant.txid_hex);
    entry.pushKV("wtxid", variant.wtxid_hex);
    return entry;
}

UniValue CorpusToUniValue(const btx::test::shielded::AdversarialProofCorpus& corpus)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("family", corpus.family_name);
    out.pushKV("base_tx_hex", corpus.base_tx_hex);
    out.pushKV("base_txid", corpus.base_txid_hex);
    out.pushKV("base_wtxid", corpus.base_wtxid_hex);

    UniValue variants(UniValue::VARR);
    for (const auto& variant : corpus.variants) {
        variants.push_back(VariantToUniValue(variant));
    }
    out.pushKV("variants", std::move(variants));
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        fs::path output_path;
        const ParsedArgs args = ParseArgs(argc, argv, output_path);

        std::string reject_reason;
        const auto corpus = btx::test::shielded::BuildV2SendAdversarialProofCorpus(
            args.base_tx_hex,
            reject_reason);
        if (!corpus.has_value()) {
            throw std::runtime_error(
                reject_reason.empty() ? "failed to build adversarial proof corpus" : reject_reason);
        }

        const std::string json = CorpusToUniValue(*corpus).write(2) + '\n';
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
        std::cerr << "gen_shielded_v2_adversarial_proof_corpus: " << e.what() << '\n';
        return 1;
    }
}
