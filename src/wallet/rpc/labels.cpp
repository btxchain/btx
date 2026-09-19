// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <key_io.h>
#include <rpc/util.h>
#include <util/bip32.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <cstdio>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <system_error>
#include <variant>

namespace wallet {
namespace {

//! Same fail-closed path policy as dumpwallet: reject empty, controls, and "..".
void EnsureSafeLabelFilePath(const std::string& dest, const char* what)
{
    if (dest.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not be empty", what));
    }
    for (const unsigned char c : dest) {
        if (c < 0x20 || c == 0x7f) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not contain control characters", what));
        }
    }
    const fs::path path = fs::u8path(dest);
    for (const auto& component : path) {
        if (component == "..") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not contain parent-directory components", what));
        }
    }
}

class ExclusiveTextFile
{
    FILE* m_fp{nullptr};

public:
    explicit ExclusiveTextFile(const fs::path& path)
    {
        m_fp = fsbridge::fopen(path, "wbx");
    }
    ExclusiveTextFile(const ExclusiveTextFile&) = delete;
    ExclusiveTextFile& operator=(const ExclusiveTextFile&) = delete;
    ~ExclusiveTextFile() { close(); }

    bool is_open() const { return m_fp != nullptr; }

    ExclusiveTextFile& operator<<(const std::string& s)
    {
        if (m_fp && !s.empty()) {
            if (std::fwrite(s.data(), 1, s.size(), m_fp) != s.size()) {
                std::fclose(m_fp);
                m_fp = nullptr;
            }
        }
        return *this;
    }

    void close()
    {
        if (m_fp) {
            std::fclose(m_fp);
            m_fp = nullptr;
        }
    }
};

void SetOwnerOnlyFilePermissions(const fs::path& path)
{
#ifndef WIN32
    std::error_code ec;
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
#else
    (void)path;
#endif
}

bool IsBitcoinUri(const std::string& ref)
{
    return ToLower(ref).starts_with("bitcoin:");
}

//! Compact BIP329 origin ([fingerprint/path]). Public metadata only — never a key.
std::optional<std::string> Bip329Origin(const CWallet& wallet, const CTxDestination& dest)
{
    const CScript script = GetScriptForDestination(dest);
    const auto spk_mans = wallet.GetScriptPubKeyMans(script);
    if (spk_mans.empty()) return std::nullopt;
    const std::unique_ptr<CKeyMetadata> meta = (*spk_mans.begin())->GetMetadata(dest);
    if (!meta || !meta->has_key_origin) return std::nullopt;
    return strprintf("[%s%s]", HexStr(meta->key_origin.fingerprint),
                     FormatHDKeypath(meta->key_origin.path, /*apostrophe=*/false));
}

void RejectNonP2MRRef(const std::string& ref, int line_no)
{
    if (IsBitcoinUri(ref)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           strprintf("importlabels line %d: bitcoin: URIs are rejected", line_no));
    }
    std::string error_msg;
    const CTxDestination dest = DecodeDestination(ref, error_msg);
    if (!IsValidDestination(dest) || !std::holds_alternative<WitnessV2P2MR>(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           strprintf("importlabels line %d: ref is not a P2MR address (secp/legacy destinations are rejected)%s",
                                     line_no,
                                     error_msg.empty() ? "" : strprintf(": %s", error_msg)));
    }
}

} // namespace

RPCHelpMan exportlabels()
{
    return RPCHelpMan{"exportlabels",
        "\nExport address labels as BIP329 JSONL (one JSON object per line).\n"
        "Each record has type, ref, label, and optional origin. Default export is labels only — not keys — so the wallet does not need to be unlocked.\n"
        "Only P2MR addresses are written. The destination file is created exclusively and must not already exist; the path must not contain '..'.\n",
        {
            {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "Server-side file path (absolute path recommended). Created exclusively; the path must not already exist."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "filename", "The filename with full absolute path"},
                {RPCResult::Type::NUM, "labels", "Number of BIP329 addr records written"},
            }
        },
        RPCExamples{
            HelpExampleCli("exportlabels", "\"labels.jsonl\"")
            + HelpExampleRpc("exportlabels", "\"labels.jsonl\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::string dest = request.params[0].get_str();
    EnsureSafeLabelFilePath(dest, "exportlabels destination");
    fs::path filepath = fs::absolute(fs::u8path(dest));

    LOCK(pwallet->cs_wallet);

    // Labels are not keys; origin is public BIP32 metadata. Do not unlock.

    if (fs::exists(filepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, filepath.utf8string() + " already exists. If you are sure this is what you want, move it out of the way first");
    }

    ExclusiveTextFile file{filepath};
    if (!file.is_open()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open labels export file");
    }

    int written{0};
    pwallet->ForEachAddrBookEntry([&](const CTxDestination& address, const std::string& label, bool is_change, const std::optional<AddressPurpose>&) {
        if (is_change) return;
        if (!std::holds_alternative<WitnessV2P2MR>(address)) return;

        UniValue rec(UniValue::VOBJ);
        rec.pushKV("type", "addr");
        rec.pushKV("ref", EncodeDestination(address));
        rec.pushKV("label", label);
        if (const auto origin = Bip329Origin(*pwallet, address)) {
            rec.pushKV("origin", *origin);
        }
        file << rec.write() + "\n";
        ++written;
    });

    if (!file.is_open()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to write labels export file");
    }
    file.close();
    SetOwnerOnlyFilePermissions(filepath);

    UniValue reply(UniValue::VOBJ);
    reply.pushKV("filename", filepath.utf8string());
    reply.pushKV("labels", written);
    return reply;
},
    };
}

RPCHelpMan importlabels()
{
    return RPCHelpMan{"importlabels",
        "\nImport BIP329 JSONL address labels (type/ref/label, optional origin).\n"
        "Only type=addr records are applied. Other BIP329 types are skipped. bitcoin: URIs and secp/legacy addresses are rejected and abort the import (nothing is written).\n"
        "origin is ignored: this RPC sets labels only, not keys, and does not require the wallet to be unlocked.\n"
        "The path must not contain '..'.\n",
        {
            {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "Server-side BIP329 JSONL file path (absolute path recommended)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "imported", "Number of P2MR address labels applied"},
                {RPCResult::Type::NUM, "skipped", "Number of non-addr BIP329 records skipped"},
            }
        },
        RPCExamples{
            HelpExampleCli("importlabels", "\"labels.jsonl\"")
            + HelpExampleRpc("importlabels", "\"labels.jsonl\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::string dest = request.params[0].get_str();
    EnsureSafeLabelFilePath(dest, "importlabels source");
    const fs::path filepath = fs::absolute(fs::u8path(dest));

    if (!fs::exists(filepath) || !fs::is_regular_file(filepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open labels import file");
    }

    std::ifstream file{filepath};
    if (!file.is_open()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open labels import file");
    }

    // Validate the whole file first (fail closed), then apply.
    std::map<CTxDestination, std::string> pending;
    int skipped{0};
    int line_no{0};
    std::string raw_line;
    while (std::getline(file, raw_line)) {
        ++line_no;
        const std::string line = util::TrimString(raw_line);
        if (line.empty()) continue;

        UniValue rec;
        if (!rec.read(line) || !rec.isObject()) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                               strprintf("importlabels line %d: expected a JSON object", line_no));
        }
        if (!rec.exists("type") || !rec["type"].isStr()) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                               strprintf("importlabels line %d: missing string field \"type\"", line_no));
        }
        const std::string type = rec["type"].get_str();
        if (type != "addr") {
            ++skipped;
            continue;
        }
        if (!rec.exists("ref") || !rec["ref"].isStr()) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                               strprintf("importlabels line %d: addr record missing string field \"ref\"", line_no));
        }
        if (!rec.exists("label") || !rec["label"].isStr()) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                               strprintf("importlabels line %d: addr record missing string field \"label\"", line_no));
        }
        const std::string ref = rec["ref"].get_str();
        RejectNonP2MRRef(ref, line_no);
        const std::string label = LabelFromValue(rec["label"]);
        pending[DecodeDestination(ref)] = label;
    }

    LOCK(pwallet->cs_wallet);
    for (const auto& [address, label] : pending) {
        if (pwallet->IsMine(address)) {
            pwallet->SetAddressBook(address, label, AddressPurpose::RECEIVE);
        } else {
            pwallet->SetAddressBook(address, label, AddressPurpose::SEND);
        }
    }

    UniValue reply(UniValue::VOBJ);
    reply.pushKV("imported", static_cast<int>(pending.size()));
    reply.pushKV("skipped", skipped);
    return reply;
},
    };
}
} // namespace wallet
