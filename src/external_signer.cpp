// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <external_signer.h>

#include <chainparams.h>
#include <common/run_command.h>
#include <core_io.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
bool IsP2MRScriptPubKey(const CScript& script_pub_key)
{
    int witness_version = 0;
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) return false;
    return witness_version == 2 && witness_program.size() == WITNESS_V2_P2MR_SIZE;
}

bool GetInputPrevoutScript(const PartiallySignedTransaction& psbt, const size_t input_index, CScript& script_out)
{
    const PSBTInput& input = psbt.inputs.at(input_index);
    const CTxIn& txin = psbt.tx->vin.at(input_index);
    if (!input.witness_utxo.IsNull()) {
        script_out = input.witness_utxo.scriptPubKey;
        return true;
    }
    if (input.non_witness_utxo && txin.prevout.n < input.non_witness_utxo->vout.size()) {
        script_out = input.non_witness_utxo->vout.at(txin.prevout.n).scriptPubKey;
        return true;
    }
    return false;
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

bool HasMatchingP2MRFingerprintForPubKey(
    const PSBTInput& input,
    Span<const unsigned char> signer_fingerprint,
    const std::vector<unsigned char>& pubkey)
{
    const auto path_it = input.m_p2mr_bip32_paths.find(pubkey);
    if (path_it == input.m_p2mr_bip32_paths.end()) return false;

    KeyOriginInfo key_origin;
    if (!DeserializeP2MRKeyOriginBytes(path_it->second, key_origin)) return false;
    return std::ranges::equal(signer_fingerprint, key_origin.fingerprint);
}

bool ValidateP2MRSignerPreconditions(
    const PartiallySignedTransaction& psbt,
    Span<const unsigned char> signer_fingerprint,
    const std::string& signer_fingerprint_hex,
    std::string& error)
{
    for (size_t input_index = 0; input_index < psbt.inputs.size(); ++input_index) {
        const PSBTInput& input = psbt.inputs[input_index];
        const bool request_has_p2mr_material =
            !input.m_p2mr_leaf_script.empty() ||
            !input.m_p2mr_control_block.empty() ||
            !input.m_p2mr_pq_sigs.empty() ||
            !input.m_p2mr_csfs_msgs.empty() ||
            !input.m_p2mr_csfs_sigs.empty() ||
            !input.m_p2mr_bip32_paths.empty() ||
            !input.m_p2mr_merkle_root.IsNull();

        CScript prevout_script;
        const bool has_prevout_script = GetInputPrevoutScript(psbt, input_index, prevout_script);
        if (request_has_p2mr_material && !has_prevout_script) {
            error = strprintf("Input %u missing prevout script for P2MR metadata", input_index);
            return false;
        }
        if (!has_prevout_script) continue;
        const bool prevout_is_p2mr = IsP2MRScriptPubKey(prevout_script);
        if (request_has_p2mr_material && !prevout_is_p2mr) {
            error = strprintf("Input %u non-P2MR prevout script has P2MR metadata", input_index);
            return false;
        }
        if (!prevout_is_p2mr) continue;

        int witness_version = 0;
        std::vector<unsigned char> witness_program;
        if (!prevout_script.IsWitnessProgram(witness_version, witness_program) ||
            witness_version != 2 || witness_program.size() != WITNESS_V2_P2MR_SIZE) {
            error = strprintf("Input %u has malformed P2MR prevout script", input_index);
            return false;
        }
        if (input.m_p2mr_leaf_script.empty() || input.m_p2mr_control_block.empty() ||
            input.m_p2mr_merkle_root.IsNull() || input.m_p2mr_bip32_paths.empty()) {
            error = strprintf("Input %u missing required P2MR metadata", input_index);
            return false;
        }
        if (ToByteVector(input.m_p2mr_merkle_root) != witness_program) {
            error = strprintf("Input %u P2MR merkle root does not match prevout commitment", input_index);
            return false;
        }
        const uint8_t control_leaf_version = input.m_p2mr_control_block.front() & P2MR_LEAF_MASK;
        if (control_leaf_version != input.m_p2mr_leaf_version) {
            error = strprintf("Input %u selected P2MR control block leaf version mismatch", input_index);
            return false;
        }
        if (input.m_p2mr_leaf_version != P2MR_LEAF_VERSION) {
            error = strprintf("Input %u has unsupported P2MR leaf version", input_index);
            return false;
        }
        const uint256 leaf_hash = ComputeP2MRLeafHash(input.m_p2mr_leaf_version, input.m_p2mr_leaf_script);
        if (!VerifyP2MRCommitment(input.m_p2mr_control_block, witness_program, leaf_hash)) {
            error = strprintf("Input %u selected P2MR leaf does not match prevout commitment", input_index);
            return false;
        }
        bool has_matching_fingerprint = false;
        for (const auto& [pubkey, key_origin_bytes] : input.m_p2mr_bip32_paths) {
            KeyOriginInfo key_origin;
            if (!DeserializeP2MRKeyOriginBytes(key_origin_bytes, key_origin)) {
                error = strprintf("Input %u has invalid P2MR BIP32 derivation encoding for pubkey size %u",
                                  input_index, pubkey.size());
                return false;
            }
            if (std::ranges::equal(signer_fingerprint, key_origin.fingerprint)) has_matching_fingerprint = true;
        }
        if (!has_matching_fingerprint) {
            error = strprintf("Signer fingerprint %s does not match any P2MR derivation fingerprint for input %u",
                              signer_fingerprint_hex, input_index);
            return false;
        }
    }
    return true;
}

bool IsDefinedP2MRSighashType(const uint8_t hash_type)
{
    const uint8_t base_type = hash_type & ~SIGHASH_ANYONECANPAY;
    return base_type == SIGHASH_ALL || base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE;
}

size_t ExpectedPQSignatureSize(const size_t pubkey_size)
{
    if (pubkey_size == MLDSA44_PUBKEY_SIZE) return MLDSA44_SIGNATURE_SIZE;
    if (pubkey_size == SLHDSA128S_PUBKEY_SIZE) return SLHDSA128S_SIGNATURE_SIZE;
    return 0;
}

bool IsWellFormedP2MRPartialSignature(const std::vector<unsigned char>& pubkey, const std::vector<unsigned char>& sig)
{
    const size_t expected_sig_size = ExpectedPQSignatureSize(pubkey.size());
    if (expected_sig_size == 0) return false;
    if (sig.size() == expected_sig_size) return true;
    return sig.size() == expected_sig_size + 1 && IsDefinedP2MRSighashType(sig.back());
}

bool IsWellFormedP2MRCSFSSignature(const std::vector<unsigned char>& pubkey, const std::vector<unsigned char>& sig)
{
    const size_t expected_sig_size = ExpectedPQSignatureSize(pubkey.size());
    return expected_sig_size != 0 && sig.size() == expected_sig_size;
}

bool HasSameUnsignedTx(const PartiallySignedTransaction& lhs, const PartiallySignedTransaction& rhs)
{
    if (!lhs.tx.has_value() || !rhs.tx.has_value()) return false;
    DataStream lhs_stream{};
    DataStream rhs_stream{};
    lhs_stream << TX_NO_WITNESS_WITH_SHIELDED(lhs.tx.value());
    rhs_stream << TX_NO_WITNESS_WITH_SHIELDED(rhs.tx.value());
    return lhs_stream.str() == rhs_stream.str();
}

bool IsValidSignerFingerprint(const std::string& fingerprint)
{
    return fingerprint.size() == sizeof(uint32_t) * 2 && IsHex(fingerprint) &&
           ParseHex(fingerprint).size() == sizeof(uint32_t);
}

bool IsSupportedExternalSignerChain(const std::string& chain)
{
    static constexpr std::array<const char*, 6> SUPPORTED_CHAINS{
        "main", "test", "testnet4", "signet", "regtest", "shieldedv2dev"};
    return std::ranges::any_of(SUPPORTED_CHAINS, [&](const char* candidate) {
        return chain == candidate;
    });
}

bool IsSafeExternalSignerDescriptorArg(const std::string& descriptor)
{
    return !std::ranges::any_of(descriptor, [](unsigned char c) {
        // Keep descriptor argv values locale-independent and tokenization-safe.
        // Reject ASCII control bytes (0x00-0x1f, 0x7f) and ASCII space.
        return c <= 0x20 || c == 0x7f;
    });
}

bool ValidateExternalSignerP2MRSignatures(
    const PartiallySignedTransaction& request_psbt,
    const PartiallySignedTransaction& signer_psbt,
    Span<const unsigned char> signer_fingerprint,
    std::string& error)
{
    for (size_t input_index = 0; input_index < signer_psbt.inputs.size(); ++input_index) {
        const auto& input = signer_psbt.inputs[input_index];
        const auto& request_input = request_psbt.inputs[input_index];
        CScript prevout_script;
        const bool has_prevout_script = GetInputPrevoutScript(request_psbt, input_index, prevout_script);
        const bool prevout_is_p2mr = has_prevout_script && IsP2MRScriptPubKey(prevout_script);
        int witness_version = 0;
        std::vector<unsigned char> witness_program;
        if (prevout_is_p2mr &&
            !prevout_script.IsWitnessProgram(witness_version, witness_program)) {
            error = strprintf("Input %u has malformed P2MR prevout script", input_index);
            return false;
        }
        const bool has_p2mr_material =
            !input.m_p2mr_leaf_script.empty() ||
            !input.m_p2mr_control_block.empty() ||
            !input.m_p2mr_pq_sigs.empty() ||
            !input.m_p2mr_csfs_msgs.empty() ||
            !input.m_p2mr_csfs_sigs.empty() ||
            !input.m_p2mr_bip32_paths.empty() ||
            !input.m_p2mr_merkle_root.IsNull();

        if (!has_prevout_script && has_p2mr_material) {
            error = strprintf("Signer returned P2MR material for input %u without prevout script", input_index);
            return false;
        }
        if (has_prevout_script && !prevout_is_p2mr && has_p2mr_material) {
            error = strprintf("Signer returned P2MR material for non-P2MR input %u", input_index);
            return false;
        }
        if (!input.m_p2mr_merkle_root.IsNull()) {
            if (input.m_p2mr_merkle_root != request_input.m_p2mr_merkle_root) {
                error = strprintf("Signer returned conflicting P2MR merkle root for input %u", input_index);
                return false;
            }
            if (prevout_is_p2mr && ToByteVector(input.m_p2mr_merkle_root) != witness_program) {
                error = strprintf("Signer returned P2MR merkle root that does not match prevout commitment for input %u", input_index);
                return false;
            }
        }

        const bool request_has_selected_leaf = !request_input.m_p2mr_leaf_script.empty() && !request_input.m_p2mr_control_block.empty();
        const bool signer_has_selected_leaf = !input.m_p2mr_leaf_script.empty() && !input.m_p2mr_control_block.empty();
        if (request_has_selected_leaf && request_input.m_p2mr_leaf_version != P2MR_LEAF_VERSION) {
            error = strprintf("PSBT input %u has unsupported P2MR leaf version", input_index);
            return false;
        }
        if (signer_has_selected_leaf && input.m_p2mr_leaf_version != P2MR_LEAF_VERSION) {
            error = strprintf("Signer returned unsupported P2MR leaf version for input %u", input_index);
            return false;
        }
        if (request_has_selected_leaf && signer_has_selected_leaf &&
            (request_input.m_p2mr_leaf_script != input.m_p2mr_leaf_script ||
             request_input.m_p2mr_control_block != input.m_p2mr_control_block)) {
            error = strprintf("Signer returned conflicting selected P2MR leaf for input %u", input_index);
            return false;
        }
        const bool has_selected_leaf = request_has_selected_leaf || signer_has_selected_leaf;
        const uint256 selected_leaf_hash = request_has_selected_leaf
            ? ComputeP2MRLeafHash(P2MR_LEAF_VERSION, request_input.m_p2mr_leaf_script)
            : signer_has_selected_leaf
            ? ComputeP2MRLeafHash(P2MR_LEAF_VERSION, input.m_p2mr_leaf_script)
            : uint256{};

        const auto validate_leaf_hash = [&](const std::pair<uint256, std::vector<unsigned char>>& leaf_pubkey,
                                            const char* field_name) {
            if (!has_selected_leaf || leaf_pubkey.first == selected_leaf_hash) return true;
            error = strprintf("Signer returned %s with unexpected P2MR leaf hash for input %u", field_name, input_index);
            return false;
        };

        for (const auto& [leaf_pubkey, sig] : input.m_p2mr_pq_sigs) {
            if (!validate_leaf_hash(leaf_pubkey, "P2MR partial signature")) return false;
            if (!request_input.m_p2mr_bip32_paths.contains(leaf_pubkey.second)) {
                error = strprintf("Signer returned unexpected P2MR partial signature pubkey for input %u", input_index);
                return false;
            }
            if (!HasMatchingP2MRFingerprintForPubKey(request_input, signer_fingerprint, leaf_pubkey.second)) {
                error = strprintf("Signer returned P2MR partial signature pubkey with non-matching fingerprint for input %u", input_index);
                return false;
            }
            if (IsWellFormedP2MRPartialSignature(leaf_pubkey.second, sig)) continue;
            error = strprintf("Signer returned invalid P2MR partial signature size for input %u", input_index);
            return false;
        }

        for (const auto& [pubkey, key_origin_bytes] : input.m_p2mr_bip32_paths) {
            KeyOriginInfo signer_key_origin;
            if (!DeserializeP2MRKeyOriginBytes(key_origin_bytes, signer_key_origin)) {
                error = strprintf("Signer returned invalid P2MR BIP32 derivation encoding for input %u", input_index);
                return false;
            }
            const auto request_path_it = request_input.m_p2mr_bip32_paths.find(pubkey);
            if (request_path_it == request_input.m_p2mr_bip32_paths.end()) {
                error = strprintf("Signer returned unexpected P2MR BIP32 derivation for input %u", input_index);
                return false;
            }
            if (request_path_it->second != key_origin_bytes) {
                error = strprintf("Signer returned conflicting P2MR BIP32 derivation for input %u", input_index);
                return false;
            }
        }

        for (const auto& [leaf_pubkey, msg] : input.m_p2mr_csfs_msgs) {
            if (!validate_leaf_hash(leaf_pubkey, "P2MR CSFS message")) return false;
            const auto request_msg_it = request_input.m_p2mr_csfs_msgs.find(leaf_pubkey);
            if (request_msg_it == request_input.m_p2mr_csfs_msgs.end()) {
                error = strprintf("Signer returned unexpected P2MR CSFS message for input %u", input_index);
                return false;
            }
            if (request_msg_it->second != msg) {
                error = strprintf("Signer returned conflicting P2MR CSFS message for input %u", input_index);
                return false;
            }
            if (input.m_p2mr_csfs_sigs.contains(leaf_pubkey)) continue;
            error = strprintf("Signer returned P2MR CSFS message without signature for input %u", input_index);
            return false;
        }

        for (const auto& [leaf_pubkey, sig] : input.m_p2mr_csfs_sigs) {
            if (!validate_leaf_hash(leaf_pubkey, "P2MR CSFS signature")) return false;
            if (!request_input.m_p2mr_bip32_paths.contains(leaf_pubkey.second)) {
                error = strprintf("Signer returned unexpected P2MR CSFS signature pubkey for input %u", input_index);
                return false;
            }
            if (!HasMatchingP2MRFingerprintForPubKey(request_input, signer_fingerprint, leaf_pubkey.second)) {
                error = strprintf("Signer returned P2MR CSFS signature pubkey with non-matching fingerprint for input %u", input_index);
                return false;
            }
            if (!IsWellFormedP2MRCSFSSignature(leaf_pubkey.second, sig)) {
                error = strprintf("Signer returned invalid P2MR CSFS signature size for input %u", input_index);
                return false;
            }
            if (!input.m_p2mr_csfs_msgs.contains(leaf_pubkey)) {
                error = strprintf("Signer returned P2MR CSFS signature with missing P2MR CSFS message for input %u", input_index);
                return false;
            }
        }
    }
    return true;
}
} // namespace

ExternalSigner::ExternalSigner(const std::string& command,
                               const std::string chain,
                               const std::string& fingerprint,
                               const std::string name,
                               const bool supports_p2mr,
                               std::vector<std::string> pq_algorithms):
    m_command(command),
    m_chain(chain),
    m_fingerprint(fingerprint),
    m_name(name),
    m_supports_p2mr(supports_p2mr),
    m_pq_algorithms(std::move(pq_algorithms)) {}

std::string ExternalSigner::NetworkArg() const
{
    if (!IsSupportedExternalSignerChain(m_chain)) {
        throw std::runtime_error(strprintf("Invalid signer chain argument '%s'", m_chain));
    }
    return " --chain " + m_chain;
}

bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string chain)
{
    // Call <command> enumerate
    const UniValue result = RunCommandParseJSON(command + " enumerate");
    if (!result.isArray()) {
        throw std::runtime_error(strprintf("'%s' received invalid response, expected array of signers", command));
    }
    for (const UniValue& signer : result.getValues()) {
        // Check for error
        const UniValue& error = signer.find_value("error");
        if (!error.isNull()) {
            if (!error.isStr()) {
                throw std::runtime_error(strprintf("'%s' error", command));
            }
            throw std::runtime_error(strprintf("'%s' error: %s", command, error.getValStr()));
        }
        // Check if fingerprint is present
        const UniValue& fingerprint = signer.find_value("fingerprint");
        if (fingerprint.isNull()) {
            throw std::runtime_error(strprintf("'%s' received invalid response, missing signer fingerprint", command));
        }
        if (!fingerprint.isStr()) {
            throw std::runtime_error(strprintf("'%s' received invalid signer fingerprint", command));
        }
        const std::string& fingerprintStr{fingerprint.get_str()};
        if (!IsValidSignerFingerprint(fingerprintStr)) {
            throw std::runtime_error(strprintf("'%s' received invalid signer fingerprint", command));
        }
        // Skip duplicate signer
        bool duplicate = false;
        for (const ExternalSigner& known_signer : signers) {
            if (known_signer.m_fingerprint == fingerprintStr) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        std::string name;
        const UniValue& model_field = signer.find_value("model");
        if (model_field.isStr() && model_field.getValStr() != "") {
            name += model_field.getValStr();
        }
        bool supports_p2mr = false;
        std::vector<std::string> pq_algorithms;
        const UniValue& capabilities = signer.find_value("capabilities");
        if (capabilities.isObject()) {
            const UniValue& p2mr_field = capabilities.find_value("p2mr");
            if (p2mr_field.isBool()) supports_p2mr = p2mr_field.get_bool();

            const UniValue& pq_algos_field = capabilities.find_value("pq_algorithms");
            if (pq_algos_field.isArray()) {
                for (const UniValue& algo : pq_algos_field.getValues()) {
                    if (algo.isStr()) pq_algorithms.push_back(algo.get_str());
                }
            }
        }
        signers.emplace_back(command, chain, fingerprintStr, name, supports_p2mr, std::move(pq_algorithms));
    }
    return true;
}

UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const
{
    if (!IsSafeExternalSignerDescriptorArg(descriptor)) {
        throw std::runtime_error("Descriptor argument contains unsupported whitespace/control characters");
    }
    return RunCommandParseJSON(m_command + " --fingerprint " + m_fingerprint + NetworkArg() +
                               " displayaddress --desc " + descriptor);
}

UniValue ExternalSigner::GetDescriptors(const int account)
{
    return RunCommandParseJSON(m_command + " --fingerprint " + m_fingerprint + NetworkArg() +
                               " getdescriptors --account " + strprintf("%d", account));
}

UniValue ExternalSigner::GetP2MRPubKeys(const std::string& descriptor, uint32_t index)
{
    if (!IsSafeExternalSignerDescriptorArg(descriptor)) {
        throw std::runtime_error("Descriptor argument contains unsupported whitespace/control characters");
    }
    const std::string command = m_command + " --fingerprint " + m_fingerprint + NetworkArg() +
                                " getp2mrpubkeys --index " + strprintf("%u", index) +
                                " --desc " + descriptor;
    return RunCommandParseJSON(command);
}

bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbtx, std::string& error)
{
    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;
    // parse ExternalSigner master fingerprint
    std::vector<unsigned char> parsed_m_fingerprint = ParseHex(m_fingerprint);
    if (parsed_m_fingerprint.size() != sizeof(uint32_t)) {
        error = "Invalid signer fingerprint";
        return false;
    }
    if (!ValidateP2MRSignerPreconditions(psbtx, parsed_m_fingerprint, m_fingerprint, error)) {
        return false;
    }

    // Check if signer fingerprint matches any input master key fingerprint
    auto matches_signer_fingerprint = [&](const PSBTInput& input) {
        for (const auto& entry : input.hd_keypaths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.fingerprint)) return true;
        }
        for (const auto& entry : input.m_tap_bip32_paths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.second.fingerprint)) return true;
        }
        for (const auto& entry : input.m_p2mr_bip32_paths) {
            KeyOriginInfo key_origin;
            if (!DeserializeP2MRKeyOriginBytes(entry.second, key_origin)) continue;
            if (std::ranges::equal(parsed_m_fingerprint, key_origin.fingerprint)) return true;
        }
        return false;
    };

    if (!std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), matches_signer_fingerprint)) {
        error = "Signer fingerprint " + m_fingerprint + " does not match any of the inputs:\n" + EncodeBase64(ssTx.str());
        return false;
    }

    const std::string command = m_command + " --stdin --fingerprint " + m_fingerprint + NetworkArg();
    const std::string stdinStr = "signtx " + EncodeBase64(ssTx.str());

    const UniValue signer_result = RunCommandParseJSON(command, stdinStr);

    if (signer_result.find_value("error").isStr()) {
        error = signer_result.find_value("error").get_str();
        return false;
    }

    if (!signer_result.find_value("psbt").isStr()) {
        error = "Unexpected result from signer";
        return false;
    }

    PartiallySignedTransaction signer_psbtx;
    std::string signer_psbt_error;
    if (!DecodeBase64PSBT(signer_psbtx, signer_result.find_value("psbt").get_str(), signer_psbt_error)) {
        error = strprintf("TX decode failed %s", signer_psbt_error);
        return false;
    }
    if (!HasSameUnsignedTx(signer_psbtx, psbtx)) {
        error = "Signer returned a modified transaction";
        return false;
    }
    if (!ValidateExternalSignerP2MRSignatures(psbtx, signer_psbtx, parsed_m_fingerprint, error)) {
        return false;
    }

    PartiallySignedTransaction merged_psbtx = psbtx;
    if (!merged_psbtx.Merge(signer_psbtx)) {
        error = "Signer returned conflicting PSBT metadata";
        return false;
    }
    psbtx = std::move(merged_psbtx);

    return true;
}
