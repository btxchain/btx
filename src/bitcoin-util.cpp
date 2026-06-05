// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <pqkey.h>
#include <pubkey.h>
#include <random.h>
#include <streams.h>
#include <uint256.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <thread>

static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("grind", "Perform proof of work on hex header string");
    argsman.AddCommand("verifyupdatesig", "Verify a detached auto-update release signature offline. Args: <algo> <pubkey-hex> <file> <sig-file>; algo is ml-dsa-44, slh-dsa-128s, or secp256k1. Prints OK and exits 0 on success.");
    argsman.AddCommand("genupdatekey", "Generate an OFFLINE post-quantum auto-update release keypair. Args: [algo] (ml-dsa-44 default, or slh-dsa-128s). Prints the secret SEED (store offline -- it is the private key) and the public key hex for -autoupdatepubkey.");
    argsman.AddCommand("signupdatesig", "Sign a release artifact with an OFFLINE post-quantum release key. Args: <algo> <seed-hex> <file> [out-sig]. Writes a detached signature (default <file>.sig) that 'verifyupdatesig' and the node accept.");

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " bitcoin-util utility version " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The btx-util tool (legacy alias: bitcoin-util) provides bitcoin related functionality that does not rely on the ability to access a running node. Available [commands] are listed below.\n"
                "\n"
                "Usage:  btx-util [options] [command]\n"
                "or:     btx-util [options] grind <hex-block-header>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static void grind_task(uint32_t nBits, CBlockHeader header, uint32_t offset, uint32_t step, std::atomic<bool>& found, uint32_t& proposed_nonce)
{
    arith_uint256 target;
    bool neg, over;
    target.SetCompact(nBits, &neg, &over);
    if (target == 0 || neg || over) return;
    header.nNonce = offset;

    uint32_t finish = std::numeric_limits<uint32_t>::max() - step;
    finish = finish - (finish % step) + offset;

    while (!found && header.nNonce < finish) {
        const uint32_t next = (finish - header.nNonce < 5000*step) ? finish : header.nNonce + 5000*step;
        do {
            if (UintToArith256(header.GetHash()) <= target) {
                if (!found.exchange(true)) {
                    proposed_nonce = header.nNonce;
                }
                return;
            }
            header.nNonce += step;
        } while(header.nNonce != next);
    }
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify block header to grind";
        return EXIT_FAILURE;
    }

    CBlockHeader header;
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    uint32_t nBits = header.nBits;
    std::atomic<bool> found{false};
    uint32_t proposed_nonce{};

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency());
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(grind_task, nBits, header, i, n_tasks, std::ref(found), std::ref(proposed_nonce));
    }
    for (auto& t : threads) {
        t.join();
    }
    if (found) {
        header.nNonce = proposed_nonce;
    } else {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static std::optional<std::vector<unsigned char>> ReadAllBytes(const std::string& path)
{
    std::ifstream in{path, std::ios::binary};
    if (!in.is_open()) return std::nullopt;
    return std::vector<unsigned char>{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Mirror node::DecodeSignatureBody: accept raw/DER bytes, hex, or base64 so the installer can
// feed the same signature artifacts the node fetches.
static std::vector<unsigned char> DecodeUpdateSignature(const std::vector<unsigned char>& body)
{
    if (body.empty()) return {};
    if (body.front() == 0x30) return body; // binary DER (secp256k1)
    const std::string text = util::TrimString(std::string{reinterpret_cast<const char*>(body.data()), body.size()});
    if (!text.empty()) {
        if (IsHex(text) && text.size() % 2 == 0) {
            if (auto parsed = TryParseHex<unsigned char>(text); parsed && !parsed->empty()) return *parsed;
        }
        if (auto decoded = DecodeBase64(text); decoded && !decoded->empty()) return *decoded;
    }
    return body;
}

static std::optional<PQAlgorithm> ParsePQUpdateAlgo(const std::string& name, std::string& canonical)
{
    const std::string lower = ToLower(name);
    if (lower == "ml-dsa-44" || lower == "mldsa44") { canonical = "ml-dsa-44"; return PQAlgorithm::ML_DSA_44; }
    if (lower == "slh-dsa-128s" || lower == "slhdsa128s") { canonical = "slh-dsa-128s"; return PQAlgorithm::SLH_DSA_128S; }
    return std::nullopt;
}

// Generate an offline post-quantum auto-update release keypair. The 32-byte high-entropy SEED is the
// portable private key (the ML-DSA/SLH-DSA key is derived deterministically from it via FIPS keygen
// entropy); store the seed offline and sign with `signupdatesig`. Prints the public key hex to
// configure on nodes via -autoupdatepubkey (+ -autoupdatepubkeyalgo).
static int GenUpdateKey(const std::vector<std::string>& args, std::string& strPrint)
{
    std::string algo_name{"ml-dsa-44"};
    if (!args.empty()) {
        const auto parsed = ParsePQUpdateAlgo(args[0], algo_name);
        if (!parsed) { strPrint = "unknown algo (expected ml-dsa-44 or slh-dsa-128s): " + args[0]; return EXIT_FAILURE; }
    }
    std::string canonical;
    const auto algo = ParsePQUpdateAlgo(algo_name, canonical);

    std::array<unsigned char, 32> seed{};
    GetStrongRandBytes(seed);
    CPQKey key;
    if (!key.MakeDeterministicKey(*algo, seed)) { strPrint = "key generation failed"; return EXIT_FAILURE; }
    const auto pub = key.GetPubKey();

    strPrint = "algo=" + canonical
        + "\nseed=" + HexStr(seed)
        + "\npubkey=" + HexStr(pub)
        + "\n# The seed above IS the private key -- store it OFFLINE only. Configure nodes with:"
        + "\n#   -autoupdatepubkeyalgo=" + canonical + " -autoupdatepubkey=" + HexStr(pub);
    return EXIT_SUCCESS;
}

// Sign a release artifact (manifest, tarball, or a pinned git commit) with an offline PQ release key
// re-derived from its seed. Produces a detached signature over SHA256(file) that `verifyupdatesig`
// and the node's release-signature verifier accept (slhdsa_fips205=true, matching VerifyUpdateSig).
static int SignUpdateSig(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() < 3 || args.size() > 4) {
        strPrint = "signupdatesig requires: <algo> <seed-hex> <file> [out-sig]";
        return EXIT_FAILURE;
    }
    std::string canonical;
    const auto algo = ParsePQUpdateAlgo(args[0], canonical);
    if (!algo) { strPrint = "unknown algo (expected ml-dsa-44 or slh-dsa-128s): " + args[0]; return EXIT_FAILURE; }

    const auto seed = TryParseHex<unsigned char>(args[1]);
    if (!seed || seed->empty()) { strPrint = "invalid seed hex"; return EXIT_FAILURE; }
    const auto message = ReadAllBytes(args[2]);
    if (!message) { strPrint = "cannot read file: " + args[2]; return EXIT_FAILURE; }
    const std::string out_path = args.size() == 4 ? args[3] : (args[2] + ".sig");

    CPQKey key;
    if (!key.MakeDeterministicKey(*algo, *seed)) { strPrint = "key derivation from seed failed"; return EXIT_FAILURE; }

    uint256 digest;
    CSHA256().Write(message->data(), message->size()).Finalize(digest.begin());
    std::vector<unsigned char> sig;
    if (!key.Sign(digest, sig, /*slhdsa_fips205=*/true) || sig.empty()) { strPrint = "signing failed"; return EXIT_FAILURE; }

    std::ofstream out{out_path, std::ios::binary | std::ios::trunc};
    if (!out.is_open()) { strPrint = "cannot write signature file: " + out_path; return EXIT_FAILURE; }
    out.write(reinterpret_cast<const char*>(sig.data()), static_cast<std::streamsize>(sig.size()));
    if (!out.good()) { strPrint = "failed writing signature file: " + out_path; return EXIT_FAILURE; }
    strPrint = "wrote " + out_path + " (" + std::to_string(sig.size()) + " bytes, " + canonical + ")";
    return EXIT_SUCCESS;
}

// Offline verification of an auto-update release signature, for the installer. Verifies the
// configured PQ (ML-DSA-44/SLH-DSA-128s) or classical (secp256k1) signature over SHA256(file),
// so the installer's source/commit trust can be quantum-safe and consistent with the node.
static int VerifyUpdateSig(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 4) {
        strPrint = "verifyupdatesig requires: <algo> <pubkey-hex> <file> <sig-file>";
        return EXIT_FAILURE;
    }
    std::string algo = ToLower(args[0]);
    const std::string& pubkey_hex = args[1];
    const auto message = ReadAllBytes(args[2]);
    const auto sig_body = ReadAllBytes(args[3]);
    if (!message) { strPrint = "cannot read file: " + args[2]; return EXIT_FAILURE; }
    if (!sig_body) { strPrint = "cannot read signature file: " + args[3]; return EXIT_FAILURE; }

    const std::vector<unsigned char> signature = DecodeUpdateSignature(*sig_body);
    const auto pubkey_bytes = TryParseHex<unsigned char>(pubkey_hex);
    if (!pubkey_bytes || pubkey_bytes->empty()) { strPrint = "FAILED"; return EXIT_FAILURE; }

    uint256 digest;
    CSHA256().Write(message->data(), message->size()).Finalize(digest.begin());

    bool ok = false;
    if (algo == "secp256k1" || algo == "ecdsa") {
        const CPubKey pubkey{*pubkey_bytes};
        ok = pubkey.IsFullyValid() && pubkey.Verify(digest, signature);
    } else {
        std::optional<PQAlgorithm> pq;
        if (algo == "ml-dsa-44" || algo == "mldsa44") pq = PQAlgorithm::ML_DSA_44;
        else if (algo == "slh-dsa-128s" || algo == "slhdsa128s") pq = PQAlgorithm::SLH_DSA_128S;
        if (!pq) { strPrint = "unknown algo (expected ml-dsa-44, slh-dsa-128s, or secp256k1): " + algo; return EXIT_FAILURE; }
        if (pubkey_bytes->size() == GetPQPubKeySize(*pq) && signature.size() == GetPQSignatureSize(*pq)) {
            const CPQPubKey pubkey{*pq, *pubkey_bytes};
            ok = pubkey.Verify(digest, signature, /*slhdsa_fips205=*/true);
        }
    }
    strPrint = ok ? "OK" : "FAILED";
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

MAIN_FUNCTION
{
    WarnAboutLegacyBinaryInvocation(argv[0] ? argv[0] : "", "bitcoin-util", "btx-util");
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "verifyupdatesig") {
            ret = VerifyUpdateSig(cmd->args, strPrint);
        } else if (cmd->command == "genupdatekey") {
            ret = GenUpdateKey(cmd->args, strPrint);
        } else if (cmd->command == "signupdatesig") {
            ret = SignUpdateSig(cmd->args, strPrint);
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
