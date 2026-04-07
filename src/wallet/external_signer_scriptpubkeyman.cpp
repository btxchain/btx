// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <external_signer.h>
#include <node/types.h>
#include <script/keyorigin.h>
#include <util/strencodings.h>
#include <wallet/external_signer_scriptpubkeyman.h>

#include <iostream>
#include <algorithm>
#include <array>
#include <key_io.h>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <tuple>
#include <univalue.h>
#include <utility>
#include <vector>

using common::PSBTError;

namespace wallet {
namespace {
bool ParseSignerFingerprint(std::string fingerprint_hex, std::array<unsigned char, 4>& out)
{
    std::ranges::transform(fingerprint_hex, fingerprint_hex.begin(), [](unsigned char c) {
        return static_cast<char>(ToLower(c));
    });
    const std::vector<unsigned char> parsed = ParseHex(fingerprint_hex);
    if (parsed.size() != out.size()) return false;
    std::copy(parsed.begin(), parsed.end(), out.begin());
    return true;
}

bool DeserializeP2MRKeyOriginBytes(const std::vector<unsigned char>& key_origin_bytes, KeyOriginInfo& key_origin)
{
    if (key_origin_bytes.size() < sizeof(uint32_t) || (key_origin_bytes.size() % sizeof(uint32_t)) != 0) {
        return false;
    }
    DataStream stream{key_origin_bytes};
    try {
        key_origin = DeserializeKeyOrigin(stream, key_origin_bytes.size());
    } catch (const std::ios_base::failure&) {
        return false;
    }
    return stream.empty();
}

bool InputMatchesSignerFingerprint(const PSBTInput& input, Span<const unsigned char> signer_fingerprint)
{
    for (const auto& [_, key_origin] : input.hd_keypaths) {
        if (std::ranges::equal(signer_fingerprint, key_origin.fingerprint)) return true;
    }
    for (const auto& [_, origin_info] : input.m_tap_bip32_paths) {
        if (std::ranges::equal(signer_fingerprint, origin_info.second.fingerprint)) return true;
    }
    for (const auto& [_, key_origin_bytes] : input.m_p2mr_bip32_paths) {
        KeyOriginInfo key_origin;
        if (!DeserializeP2MRKeyOriginBytes(key_origin_bytes, key_origin)) continue;
        if (std::ranges::equal(signer_fingerprint, key_origin.fingerprint)) return true;
    }
    return false;
}

bool ParseP2MRAlgo(const std::string& algo_name, PQAlgorithm& algo_out)
{
    if (algo_name == "ml_dsa_44") {
        algo_out = PQAlgorithm::ML_DSA_44;
        return true;
    }
    if (algo_name == "slh_dsa_128s") {
        algo_out = PQAlgorithm::SLH_DSA_128S;
        return true;
    }
    return false;
}
} // namespace

bool ExternalSignerScriptPubKeyMan::SetupDescriptor(WalletBatch& batch, std::unique_ptr<Descriptor> desc)
{
    LOCK(cs_desc_man);
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));

    int64_t creation_time = GetTime();

    // Make the descriptor
    WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
    m_wallet_descriptor = w_desc;

    // Store the descriptor
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // TopUp
    TopUpWithDB(batch);

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

ExternalSigner ExternalSignerScriptPubKeyMan::GetExternalSigner() {
    auto signer{GetExternalSigner2()};
    if (!signer) throw std::runtime_error(util::ErrorString(signer).original);
    return *signer;
}

util::Result<ExternalSigner> ExternalSignerScriptPubKeyMan::GetExternalSigner2(std::optional<std::string> signer_fingerprint) {
    const std::string command = gArgs.GetArg("-signer", "");
    if (command == "") return util::Error{Untranslated("restart btxd with -signer=<cmd>")};
    std::vector<ExternalSigner> signers;
    ExternalSigner::Enumerate(command, signers, Params().GetChainTypeString());
    if (signers.empty()) return util::Error{Untranslated("No external signers found")};

    if (!signer_fingerprint.has_value()) {
        const std::string configured = gArgs.GetArg("-signerfingerprint", "");
        if (!configured.empty()) signer_fingerprint = configured;
    }

    if (signer_fingerprint.has_value()) {
        for (const auto& signer : signers) {
            if (signer.m_fingerprint == *signer_fingerprint) return signer;
        }
        return util::Error{Untranslated(strprintf("External signer with fingerprint '%s' not found", *signer_fingerprint))};
    }

    if (signers.size() > 1) return util::Error{Untranslated("More than one external signer found. Please connect only one at a time or set -signerfingerprint.")};
    return signers.front();
}

util::Result<void> ExternalSignerScriptPubKeyMan::DisplayAddress(const CTxDestination& dest, const ExternalSigner &signer) const
{
    // Construct a concrete descriptor for this destination so signer-side display can be verified.
    const CScript& scriptPubKey = GetScriptForDestination(dest);
    auto provider = GetSolvingProvider(scriptPubKey);
    auto descriptor = InferDescriptor(scriptPubKey, *provider);

    const UniValue& result = signer.DisplayAddress(descriptor->ToString());

    const UniValue& error = result.find_value("error");
    if (error.isStr()) return util::Error{strprintf(_("Signer returned error: %s"), error.getValStr())};

    const UniValue& ret_address = result.find_value("address");
    if (!ret_address.isStr()) return util::Error{_("Signer did not echo address")};

    if (ret_address.getValStr() != EncodeDestination(dest)) {
        return util::Error{strprintf(_("Signer echoed unexpected address %s"), ret_address.getValStr())};
    }

    return util::Result<void>();
}

bool ExternalSignerScriptPubKeyMan::PopulateDerivedCache(uint32_t index, DescriptorCache& cache, std::string& error) const
{
    LOCK(cs_desc_man);

    if (!m_wallet_descriptor.descriptor || !m_wallet_descriptor.descriptor->IsRange()) return false;
    const std::string descriptor = m_wallet_descriptor.descriptor->ToString();
    if (!descriptor.starts_with("mr(")) return false;

    auto signer = GetExternalSigner2();
    if (!signer) {
        error = util::ErrorString(signer).translated;
        return false;
    }

    const UniValue response = signer->GetP2MRPubKeys(descriptor, index);
    const UniValue& response_error = response.find_value("error");
    if (response_error.isStr()) {
        error = response_error.getValStr();
        return false;
    }

    const UniValue& entries = response.find_value("entries");
    if (!entries.isArray()) return false;

    bool inserted_any = false;
    for (const UniValue& entry : entries.getValues()) {
        if (!entry.isObject()) continue;
        const UniValue& expr_index = entry.find_value("expr_index");
        const UniValue& algo_name = entry.find_value("algo");
        const UniValue& pubkey_hex = entry.find_value("pubkey");
        if (!expr_index.isNum() || !algo_name.isStr() || !pubkey_hex.isStr()) continue;

        const int key_expr_index = expr_index.getInt<int>();
        if (key_expr_index < 0) continue;

        PQAlgorithm algo;
        if (!ParseP2MRAlgo(algo_name.getValStr(), algo)) continue;

        const std::string pubkey_str = pubkey_hex.getValStr();
        if (!IsHex(pubkey_str)) continue;
        const std::vector<unsigned char> pubkey = ParseHex(pubkey_str);

        const size_t expected_size = algo == PQAlgorithm::ML_DSA_44 ? MLDSA44_PUBKEY_SIZE : SLHDSA128S_PUBKEY_SIZE;
        if (pubkey.size() != expected_size) continue;

        cache.CacheDerivedPQPubKey(algo, static_cast<uint32_t>(key_expr_index), index, pubkey);
        inserted_any = true;
    }

    return inserted_any;
}

// If sign is true, transaction must previously have been filled
std::optional<PSBTError> ExternalSignerScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, int sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize) const
{
    if (!sign) {
        return DescriptorScriptPubKeyMan::FillPSBT(psbt, txdata, sighash_type, false, bip32derivs, n_signed, finalize);
    }

    auto signer{GetExternalSigner2()};
    if (!signer) {
        LogWarning("%s", util::ErrorString(signer).original);
        return PSBTError::EXTERNAL_SIGNER_NOT_FOUND;
    }

    std::array<unsigned char, 4> signer_fingerprint{};
    if (!ParseSignerFingerprint(signer->m_fingerprint, signer_fingerprint)) {
        LogWarning("External signer fingerprint '%s' is invalid", signer->m_fingerprint);
        return PSBTError::EXTERNAL_SIGNER_FAILED;
    }

    // Only require completion for inputs that belong to this signer fingerprint.
    bool has_relevant_inputs = false;
    bool relevant_inputs_complete = true;
    for (const auto& input : psbt.inputs) {
        if (!InputMatchesSignerFingerprint(input, signer_fingerprint)) continue;
        has_relevant_inputs = true;
        relevant_inputs_complete &= PSBTInputSigned(input);
    }
    if (!has_relevant_inputs || relevant_inputs_complete) return {};

    std::string failure_reason;
    if(!signer->SignTransaction(psbt, failure_reason)) {
        LogWarning("Failed to sign: %s\n", failure_reason);
        return PSBTError::EXTERNAL_SIGNER_FAILED;
    }
    if (finalize) FinalizePSBT(psbt); // This won't work in a multisig setup
    return {};
}
} // namespace wallet
