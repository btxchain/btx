// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/signer_provider.h>

#include <common/args.h>
#include <common/run_command.h>
#include <pq/pq_keyderivation.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>
#include <utility>

namespace wallet {
namespace {

UniValue PublicChildUnsupportedHealth(const std::string& backend, bool p2mr,
                                      const std::vector<std::string>& algos, const std::string& error)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("ok", error.empty());
    o.pushKV("backend", backend);
    o.pushKV("p2mr", p2mr);
    UniValue arr(UniValue::VARR);
    for (const std::string& a : algos) arr.push_back(a);
    o.pushKV("pq_algorithms", std::move(arr));
    if (!error.empty()) o.pushKV("error", error);
    o.pushKV("public_child_derivation", false);
    o.pushKV("public_child_error", SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);
    return o;
}

bool ParseBcp1KeyPath(const std::string& path, uint32_t& coin_type, uint32_t& account, uint32_t& branch,
                      uint32_t& index, std::string& error)
{
    std::vector<uint32_t> parsed;
    if (!bcp1::ParseDerivationPath(path, parsed) || parsed.size() != 5) {
        error = "INVALID_PATH";
        return false;
    }
    if (parsed[0] != (bcp1::PURPOSE | bcp1::HARDENED)) {
        error = "INVALID_PATH";
        return false;
    }
    if ((parsed[1] & bcp1::HARDENED) == 0 || (parsed[2] & bcp1::HARDENED) == 0) {
        error = "INVALID_PATH";
        return false;
    }
    if ((parsed[3] & bcp1::HARDENED) != 0 || (parsed[4] & bcp1::HARDENED) != 0) {
        error = "INVALID_PATH";
        return false;
    }
    if (parsed[3] != bcp1::BRANCH_DEPOSIT && parsed[3] != bcp1::BRANCH_CHANGE) {
        error = "INVALID_PATH";
        return false;
    }
    coin_type = parsed[1] & ~bcp1::HARDENED;
    account = parsed[2] & ~bcp1::HARDENED;
    branch = parsed[3];
    index = parsed[4];
    return true;
}

bool IsSafeSignerArg(const std::string& value)
{
    if (value.empty() || value.size() > 256) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '/' || c == '\'' || c == '-' || c == '_' || c == 'h' || c == 'H';
    });
}

bool HostIsLoopback(const std::string& host)
{
    const std::string h = ToLower(host);
    if (h == "localhost" || h == "::1" || h == "[::1]") return true;
    int a = -1, b = -1, c = -1, d = -1;
    if (sscanf(h.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        return a == 127 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255;
    }
    return false;
}

bool UrlIsLoopbackHttp(const std::string& url, std::string& error)
{
    const std::string lower = ToLower(url);
    if (!lower.starts_with("http://") && !lower.starts_with("https://")) {
        error = SignerProvider::ERR_HTTPS_NOT_LOOPBACK;
        return false;
    }
    const size_t scheme = url.find("://");
    std::string rest = url.substr(scheme + 3);
    if (rest.find('@') != std::string::npos) {
        error = SignerProvider::ERR_HTTPS_NOT_LOOPBACK;
        return false;
    }
    std::string host;
    if (!rest.empty() && rest.front() == '[') {
        const auto end = rest.find(']');
        if (end == std::string::npos || end < 2) {
            error = SignerProvider::ERR_HTTPS_NOT_LOOPBACK;
            return false;
        }
        host = rest.substr(1, end - 1);
    } else {
        const auto cut = rest.find_first_of(":/");
        host = cut == std::string::npos ? rest : rest.substr(0, cut);
    }
    if (!HostIsLoopback(host)) {
        error = SignerProvider::ERR_HTTPS_NOT_LOOPBACK;
        return false;
    }
    return true;
}

} // namespace

CommandSigner::CommandSigner(std::string command, std::string chain, ExternalSigner signer)
    : m_command(std::move(command)), m_chain(std::move(chain)), m_signer(std::move(signer))
{
}

std::string CommandSigner::NetworkArg() const
{
    return " --chain " + m_chain;
}

bool CommandSigner::SafeArg(const std::string& value) const
{
    return IsSafeSignerArg(value);
}

bool CommandSigner::GetPublicKey(const std::string& path, PQAlgorithm algo,
                                 std::vector<unsigned char>& pubkey, std::string& error)
{
    pubkey.clear();
    if (!SafeArg(path) || !SafeArg(bcp1::FormatAlgo(algo))) {
        error = "INVALID_PATH";
        return false;
    }
    try {
        const std::string cmd = m_command + " --fingerprint " + m_signer.m_fingerprint + NetworkArg() +
                                " getpubkey --path " + path + " --algo " + bcp1::FormatAlgo(algo);
        const UniValue result = RunCommandParseJSON(cmd);
        if (result.find_value("error").isStr()) {
            error = result.find_value("error").get_str();
            return false;
        }
        if (!result.find_value("pubkey").isStr()) {
            error = "SIGNER_PUBKEY_MISSING";
            return false;
        }
        const std::string hex = result.find_value("pubkey").get_str();
        if (!IsHex(hex)) {
            error = "SIGNER_PUBKEY_MISSING";
            return false;
        }
        pubkey = ParseHex(hex);
        if (pubkey.size() != GetPQPubKeySize(algo)) {
            error = "SIGNER_PUBKEY_MISSING";
            pubkey.clear();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

bool CommandSigner::DerivePublicKey(Span<const unsigned char>, const std::string&, PQAlgorithm,
                                    std::vector<unsigned char>& pubkey, std::string& error)
{
    // ML-DSA-44 (and BCP/1 SLH-DSA) keys are seed-hardened only: m/87h/... from
    // the signer master seed. There is no BIP32 public-child operator.
    pubkey.clear();
    error = ERR_PUBLIC_CHILD_UNSUPPORTED;
    return false;
}

bool CommandSigner::SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                               std::vector<unsigned char>& signature, std::string& error)
{
    signature.clear();
    if (!SafeArg(path) || !SafeArg(bcp1::FormatAlgo(algo))) {
        error = "INVALID_PATH";
        return false;
    }
    try {
        UniValue req(UniValue::VOBJ);
        req.pushKV("path", path);
        req.pushKV("algo", bcp1::FormatAlgo(algo));
        req.pushKV("digest", digest.GetHex());
        const std::string command = m_command + " --stdin --fingerprint " + m_signer.m_fingerprint + NetworkArg();
        const std::string stdin_str = "signdigest " + req.write();
        const UniValue result = RunCommandParseJSON(command, stdin_str);
        if (result.find_value("error").isStr()) {
            error = result.find_value("error").get_str();
            return false;
        }
        if (!result.find_value("signature").isStr()) {
            error = "SIGNER_SIGNATURE_MISSING";
            return false;
        }
        const std::string hex = result.find_value("signature").get_str();
        if (!IsHex(hex)) {
            error = "SIGNER_SIGNATURE_MISSING";
            return false;
        }
        signature = ParseHex(hex);
        if (signature.size() != GetPQSignatureSize(algo) &&
            signature.size() != GetPQSignatureSize(algo) + 1) {
            error = "SIGNER_SIGNATURE_MISSING";
            signature.clear();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

UniValue CommandSigner::Health() const
{
    try {
        const std::string cmd = m_command + " --fingerprint " + m_signer.m_fingerprint + NetworkArg() + " health";
        UniValue result = RunCommandParseJSON(cmd);
        if (!result.isObject()) result = UniValue(UniValue::VOBJ);
        if (result.find_value("error").isStr()) {
            UniValue o = PublicChildUnsupportedHealth("command", m_signer.SupportsP2MR(),
                                                      m_signer.SupportedPQAlgorithms(),
                                                      result.find_value("error").get_str());
            o.pushKV("ok", false);
            return o;
        }
        result.pushKV("backend", "command");
        if (!result.exists("ok")) result.pushKV("ok", true);
        if (!result.exists("p2mr")) result.pushKV("p2mr", m_signer.SupportsP2MR());
        if (!result.exists("public_child_derivation")) result.pushKV("public_child_derivation", false);
        if (!result.exists("public_child_error")) {
            result.pushKV("public_child_error", SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);
        }
        return result;
    } catch (const std::exception& e) {
        return PublicChildUnsupportedHealth("command", /*p2mr=*/false, {}, e.what());
    }
}

bool CommandSigner::SignTransaction(PartiallySignedTransaction& psbt, std::string& error)
{
    return m_signer.SignTransaction(psbt, error);
}

SoftwareSigner::SoftwareSigner(Span<const unsigned char> master_seed, bool test_only)
    : m_seed(master_seed.begin(), master_seed.end()), m_test_only(test_only)
{
}

SoftwareSigner::~SoftwareSigner()
{
    if (!m_seed.empty()) {
        memory_cleanse(m_seed.data(), m_seed.size());
        m_seed.clear();
    }
}

bool SoftwareSigner::GetPublicKey(const std::string& path, PQAlgorithm algo,
                                  std::vector<unsigned char>& pubkey, std::string& error)
{
    pubkey.clear();
    uint32_t coin_type = 0, account = 0, branch = 0, index = 0;
    if (!ParseBcp1KeyPath(path, coin_type, account, branch, index, error)) return false;
    const auto key = pq::DerivePQKeyFromBIP39(Span<const unsigned char>{m_seed.data(), m_seed.size()}, algo,
                                             coin_type, account, branch, index);
    if (!key || !key->IsValid()) {
        error = "DERIVE_FAILED";
        return false;
    }
    pubkey = key->GetPubKey();
    return true;
}

bool SoftwareSigner::DerivePublicKey(Span<const unsigned char>, const std::string&, PQAlgorithm,
                                     std::vector<unsigned char>& pubkey, std::string& error)
{
    // ML-DSA-44 cannot do Bitcoin-style non-hardened public child derivation.
    // BCP/1 keys are seed-hardened only (pq::DerivePQKeyFromBIP39 / GetPublicKey).
    pubkey.clear();
    error = ERR_PUBLIC_CHILD_UNSUPPORTED;
    return false;
}

bool SoftwareSigner::SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                                std::vector<unsigned char>& signature, std::string& error)
{
    signature.clear();
    uint32_t coin_type = 0, account = 0, branch = 0, index = 0;
    if (!ParseBcp1KeyPath(path, coin_type, account, branch, index, error)) return false;
    const auto key = pq::DerivePQKeyFromBIP39(Span<const unsigned char>{m_seed.data(), m_seed.size()}, algo,
                                             coin_type, account, branch, index);
    if (!key || !key->IsValid()) {
        error = "DERIVE_FAILED";
        return false;
    }
    if (!key->Sign(digest, signature)) {
        error = "SIGN_FAILED";
        signature.clear();
        return false;
    }
    return true;
}

UniValue SoftwareSigner::Health() const
{
    UniValue o = PublicChildUnsupportedHealth("software", /*p2mr=*/true,
                                              {"ml_dsa_44", "slh_dsa_128s"}, "");
    o.pushKV("test_only", m_test_only);
    return o;
}

LoopbackHttpsSigner::LoopbackHttpsSigner(std::string url) : m_url(std::move(url)) {}

bool LoopbackHttpsSigner::GetPublicKey(const std::string&, PQAlgorithm, std::vector<unsigned char>& pubkey,
                                       std::string& error)
{
    pubkey.clear();
    error = ERR_HTTPS_UNAVAILABLE;
    return false;
}

bool LoopbackHttpsSigner::DerivePublicKey(Span<const unsigned char>, const std::string&, PQAlgorithm,
                                          std::vector<unsigned char>& pubkey, std::string& error)
{
    pubkey.clear();
    error = ERR_PUBLIC_CHILD_UNSUPPORTED;
    return false;
}

bool LoopbackHttpsSigner::SignDigest(const std::string&, PQAlgorithm, const uint256&,
                                     std::vector<unsigned char>& signature, std::string& error)
{
    signature.clear();
    error = ERR_HTTPS_UNAVAILABLE;
    return false;
}

UniValue LoopbackHttpsSigner::Health() const
{
    UniValue o = PublicChildUnsupportedHealth("https", /*p2mr=*/false, {}, ERR_HTTPS_UNAVAILABLE);
    o.pushKV("url", m_url);
    return o;
}

Pkcs11Signer::Pkcs11Signer(std::string module_path) : m_module_path(std::move(module_path)) {}

bool Pkcs11Signer::GetPublicKey(const std::string&, PQAlgorithm, std::vector<unsigned char>& pubkey,
                               std::string& error)
{
    pubkey.clear();
    error = ERR_PKCS11_LIB_MISSING;
    return false;
}

bool Pkcs11Signer::DerivePublicKey(Span<const unsigned char>, const std::string&, PQAlgorithm,
                                   std::vector<unsigned char>& pubkey, std::string& error)
{
    pubkey.clear();
    error = ERR_PUBLIC_CHILD_UNSUPPORTED;
    return false;
}

bool Pkcs11Signer::SignDigest(const std::string&, PQAlgorithm, const uint256&,
                              std::vector<unsigned char>& signature, std::string& error)
{
    signature.clear();
    error = ERR_PKCS11_UNAVAILABLE;
    return false;
}

UniValue Pkcs11Signer::Health() const
{
    UniValue o = PublicChildUnsupportedHealth("pkcs11", /*p2mr=*/false, {}, ERR_PKCS11_LIB_MISSING);
    if (!m_module_path.empty()) o.pushKV("module", m_module_path);
    return o;
}

KmipSigner::KmipSigner(std::string server_uri) : m_server_uri(std::move(server_uri)) {}

bool KmipSigner::GetPublicKey(const std::string&, PQAlgorithm, std::vector<unsigned char>& pubkey,
                              std::string& error)
{
    pubkey.clear();
    error = ERR_KMIP_LIB_MISSING;
    return false;
}

bool KmipSigner::DerivePublicKey(Span<const unsigned char>, const std::string&, PQAlgorithm,
                                 std::vector<unsigned char>& pubkey, std::string& error)
{
    pubkey.clear();
    error = ERR_PUBLIC_CHILD_UNSUPPORTED;
    return false;
}

bool KmipSigner::SignDigest(const std::string&, PQAlgorithm, const uint256&,
                            std::vector<unsigned char>& signature, std::string& error)
{
    signature.clear();
    error = ERR_KMIP_UNAVAILABLE;
    return false;
}

UniValue KmipSigner::Health() const
{
    UniValue o = PublicChildUnsupportedHealth("kmip", /*p2mr=*/false, {}, ERR_KMIP_LIB_MISSING);
    if (!m_server_uri.empty()) o.pushKV("uri", m_server_uri);
    return o;
}

std::unique_ptr<SignerProvider> MakeCommandSigner(const std::string& command, const std::string& chain,
                                                  const std::optional<std::string>& fingerprint,
                                                  std::string& error)
{
    if (command.empty()) {
        error = "restart btxd with -signer=<cmd>";
        return nullptr;
    }
    try {
        std::vector<ExternalSigner> signers;
        ExternalSigner::Enumerate(command, signers, chain);
        if (signers.empty()) {
            error = "No external signers found";
            return nullptr;
        }
        if (fingerprint.has_value()) {
            for (auto& signer : signers) {
                if (signer.m_fingerprint == *fingerprint) {
                    return std::make_unique<CommandSigner>(command, chain, std::move(signer));
                }
            }
            error = strprintf("External signer with fingerprint '%s' not found", *fingerprint);
            return nullptr;
        }
        if (signers.size() > 1) {
            error = "More than one external signer found. Set fingerprint.";
            return nullptr;
        }
        return std::make_unique<CommandSigner>(command, chain, std::move(signers.front()));
    } catch (const std::exception& e) {
        error = e.what();
        return nullptr;
    }
}

std::unique_ptr<SignerProvider> MakeSoftwareSigner(ChainType chain, Span<const unsigned char> master_seed,
                                                   const ArgsManager& args, std::string& error)
{
    if (chain != ChainType::REGTEST) {
        error = SignerProvider::ERR_SOFTWARE_SIGNER_REGTEST_ONLY;
        return nullptr;
    }
    if (!args.GetBoolArg("-bcp1software", false)) {
        error = SignerProvider::ERR_SOFTWARE_SIGNER_DISABLED;
        return nullptr;
    }
    if (master_seed.empty()) {
        error = "SOFTWARE_SIGNER_EMPTY_SEED";
        return nullptr;
    }
    return std::make_unique<SoftwareSigner>(master_seed, /*test_only=*/false);
}

std::unique_ptr<SignerProvider> MakeSoftwareSignerForTests(Span<const unsigned char> master_seed)
{
    return std::make_unique<SoftwareSigner>(master_seed, /*test_only=*/true);
}

std::unique_ptr<SignerProvider> MakeLoopbackHttpsSigner(const std::string& url, std::string& error)
{
    if (!UrlIsLoopbackHttp(url, error)) return nullptr;
    return std::make_unique<LoopbackHttpsSigner>(url);
}

std::unique_ptr<SignerProvider> MakePkcs11Signer(const std::string& module_path, std::string& error)
{
    error.clear();
    return std::make_unique<Pkcs11Signer>(module_path);
}

std::unique_ptr<SignerProvider> MakeKmipSigner(const std::string& server_uri, std::string& error)
{
    error.clear();
    return std::make_unique<KmipSigner>(server_uri);
}

bool SignBcp1Package(SignerProvider& signer, bcp1::Package& pkg, std::string& error)
{
    if (!bcp1::FillCanonicalDigests(pkg, error)) return false;
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        bcp1::Input& in = pkg.inputs[i];
        if (!in.derivation_path.has_value() || !in.algo.has_value() || !in.digest.has_value()) {
            error = bcp1::ERR_NOT_READY;
            return false;
        }
        std::vector<unsigned char> signature;
        if (!signer.SignDigest(*in.derivation_path, *in.algo, *in.digest, signature, error)) return false;
        if (!bcp1::InsertSignature(pkg, i, in.pubkey, signature, error)) return false;
    }
    return true;
}

} // namespace wallet
