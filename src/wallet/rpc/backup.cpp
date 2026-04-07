// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chain.h>
#include <clientversion.h>
#include <codex32.h>
#include <core_io.h>
#include <crypto/aes.h>
#include <crypto/sha512.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <random.h>
#include <key_io.h>
#include <merkleblock.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/solver.h>
#include <streams.h>
#include <support/cleanse.h>
#include <sync.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/string.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/receive.h>
#include <wallet/crypter.h>
#include <wallet/rpc/util.h>
#include <wallet/shielded_wallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <univalue.h>



using interfaces::FoundBlock;
using util::SplitString;

namespace wallet {
std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (const unsigned char c : str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr({&c, 1});
        } else {
            ret << c;
        }
    }
    return ret.str();
}

static std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) |
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

static bool GetWalletAddressesForKey(const LegacyScriptPubKeyMan* spk_man, const CWallet& wallet, const CKeyID& keyid, std::string& strAddr, std::string& strLabel) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    bool fLabelFound = false;
    CKey key;
    spk_man->GetKey(keyid, key);
    for (const auto& dest : GetAllDestinationsForKey(key.GetPubKey())) {
        const auto* address_book_entry = wallet.FindAddressBookEntry(dest);
        if (address_book_entry) {
            if (!strAddr.empty()) {
                strAddr += ",";
            }
            strAddr += EncodeDestination(dest);
            strLabel = EncodeDumpString(address_book_entry->GetLabel());
            fLabelFound = true;
        }
    }
    if (!fLabelFound) {
        strAddr = EncodeDestination(GetDestinationForKey(key.GetPubKey(), wallet.m_default_address_type));
    }
    return fLabelFound;
}

static const int64_t TIMESTAMP_MIN = 0;

static void RescanWallet(CWallet& wallet, const WalletRescanReserver& reserver, int64_t time_begin = TIMESTAMP_MIN, bool update = true)
{
    int64_t scanned_time = wallet.RescanFromTime(time_begin, reserver, update);
    if (wallet.IsAbortingRescan()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
    } else if (scanned_time > time_begin) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan was unable to fully rescan the blockchain. Some transactions may be missing.");
    }
}

static void EnsureBlockDataFromTime(const CWallet& wallet, int64_t timestamp)
{
    auto& chain{wallet.chain()};
    if (!chain.havePruned()) {
        return;
    }

    int height{0};
    const bool found{chain.findFirstBlockWithTimeAndHeight(timestamp - TIMESTAMP_WINDOW, 0, FoundBlock().height(height))};

    uint256 tip_hash{WITH_LOCK(wallet.cs_wallet, return wallet.GetLastBlockHash())};
    if (found && !chain.hasBlocks(tip_hash, height)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Pruned blocks from height %d required to import keys. Use RPC call getblockchaininfo to determine your pruned height.", height));
    }
}

static void SetOwnerOnlyPermissions(const fs::path& path, const bool is_directory)
{
#ifndef WIN32
    const fs::perms perms = is_directory
        ? (fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec)
        : (fs::perms::owner_read | fs::perms::owner_write);
    std::error_code ec;
    fs::permissions(path, perms, fs::perm_options::replace, ec);
#else
    (void)path;
    (void)is_directory;
#endif
}

static void EnsureFreshDirectory(const fs::path& path)
{
    if (fs::exists(path)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Destination already exists: %s", fs::PathToString(path)));
    }
    try {
        if (!fs::create_directories(path)) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to create destination directory %s",
                                                           fs::PathToString(path)));
        }
    } catch (const fs::filesystem_error& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to create destination directory %s: %s",
                                                       fs::PathToString(path), e.what()));
    }
    SetOwnerOnlyPermissions(path, /*is_directory=*/true);
}

static void WriteTextFile(const fs::path& path, const std::string& content)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to open %s for writing", fs::PathToString(path)));
    }
    out.write(content.data(), content.size());
    if (!out.good()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to write %s", fs::PathToString(path)));
    }
    out.close();
    SetOwnerOnlyPermissions(path, /*is_directory=*/false);
}

static void WriteJsonFile(const fs::path& path, const UniValue& value)
{
    WriteTextFile(path, value.write(2) + "\n");
}

static std::vector<unsigned char> SerializeTextBytes(const std::string& content)
{
    return std::vector<unsigned char>(content.begin(), content.end());
}

static std::vector<unsigned char> SerializeJsonBytes(const UniValue& value)
{
    return SerializeTextBytes(value.write(2) + "\n");
}

static std::string WalletBundleBackupFilename(const CWallet& wallet)
{
    const std::string base_name = fs::PathToString(fs::u8path(wallet.GetName()).filename());
    return strprintf("%s.backup.dat", base_name.empty() ? "wallet" : base_name);
}

static std::string WalletBundleDirectoryName(const CWallet& wallet)
{
    const std::string base_name = fs::PathToString(fs::u8path(wallet.GetName()).filename());
    return ValidateWalletBundleArchiveDirectoryName(strprintf("%s.bundle", base_name.empty() ? "wallet" : base_name));
}

static int32_t CurrentShieldedWalletPrivacyHeight(const CWallet& wallet)
{
    const auto tip_height = wallet.chain().getHeight();
    if (!tip_height.has_value() ||
        *tip_height < 0 ||
        *tip_height >= std::numeric_limits<int32_t>::max()) {
        return std::numeric_limits<int32_t>::max();
    }
    return *tip_height;
}

static bool DisableRawShieldedViewingKeyBundleExport(const CWallet& wallet)
{
    return Params().GetConsensus().IsShieldedMatRiCTDisabled(CurrentShieldedWalletPrivacyHeight(wallet));
}

static bool DefaultIncludeViewingKeysInWalletBundle(const CWallet& wallet)
{
    return !DisableRawShieldedViewingKeyBundleExport(wallet);
}

static void EnsureViewingKeyBundleExportAllowed(const CWallet& wallet,
                                                bool include_viewing_keys,
                                                std::string_view rpc_name)
{
    if (!include_viewing_keys || !wallet.m_shielded_wallet) {
        return;
    }
    if (!DisableRawShieldedViewingKeyBundleExport(wallet)) {
        return;
    }

    throw JSONRPCError(
        RPC_WALLET_ERROR,
        strprintf("%s viewing-key export is disabled after block %d; pass include_viewing_keys=false and use structured audit grants or the encrypted wallet backup instead",
                  rpc_name,
                  Params().GetConsensus().nShieldedMatRiCTDisableHeight));
}

static constexpr std::string_view WALLET_BUNDLE_ARCHIVE_MAGIC{"BTXWBAR1"};
static constexpr uint32_t WALLET_BUNDLE_ARCHIVE_VERSION{1};
static constexpr unsigned int WALLET_BUNDLE_ARCHIVE_DERIVATION_METHOD{0};
static constexpr unsigned int WALLET_BUNDLE_ARCHIVE_DERIVATION_ITERATIONS{250000};

struct WalletBundleArchiveFileEntry
{
    std::string path;
    std::vector<unsigned char> data;

    SERIALIZE_METHODS(WalletBundleArchiveFileEntry, obj)
    {
        READWRITE(obj.path, obj.data);
    }
};

struct WalletBundleArchivePayload
{
    std::string wallet_name;
    std::string bundle_name;
    std::string backup_file;
    std::vector<WalletBundleArchiveFileEntry> files;

    SERIALIZE_METHODS(WalletBundleArchivePayload, obj)
    {
        READWRITE(obj.wallet_name, obj.bundle_name, obj.backup_file, obj.files);
    }
};

struct WalletBundleArchiveEnvelope
{
    std::string magic;
    uint32_t version{WALLET_BUNDLE_ARCHIVE_VERSION};
    uint32_t derivation_method{WALLET_BUNDLE_ARCHIVE_DERIVATION_METHOD};
    uint32_t derivation_iterations{WALLET_BUNDLE_ARCHIVE_DERIVATION_ITERATIONS};
    std::vector<unsigned char> salt;
    uint256 plaintext_sha256;
    std::vector<unsigned char> ciphertext;

    SERIALIZE_METHODS(WalletBundleArchiveEnvelope, obj)
    {
        READWRITE(obj.magic, obj.version, obj.derivation_method, obj.derivation_iterations, obj.salt, obj.plaintext_sha256, obj.ciphertext);
    }
};

static UniValue BuildListDescriptorsResult(const CWallet& wallet, const bool priv)
{
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "listdescriptors is not available for non-descriptor wallets");
    }

    if (priv) {
        EnsureWalletIsUnlocked(wallet);
    }

    LOCK(wallet.cs_wallet);

    const auto active_spk_mans = wallet.GetActiveScriptPubKeyMans();

    struct WalletDescInfo {
        std::string descriptor;
        uint64_t creation_time;
        bool active;
        std::optional<bool> internal;
        std::optional<std::pair<int64_t, int64_t>> range;
        int64_t next_index;
    };

    std::vector<WalletDescInfo> wallet_descriptors;
    for (const auto& spk_man : wallet.GetAllScriptPubKeyMans()) {
        const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected ScriptPubKey manager type.");
        }
        LOCK(desc_spk_man->cs_desc_man);
        const auto& wallet_descriptor = desc_spk_man->GetWalletDescriptor();
        std::string descriptor;
        if (!desc_spk_man->GetDescriptorString(descriptor, priv)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Can't get descriptor string.");
        }
        const bool is_range = wallet_descriptor.descriptor->IsRange();
        wallet_descriptors.push_back({
            descriptor,
            wallet_descriptor.creation_time,
            active_spk_mans.count(desc_spk_man) != 0,
            wallet.IsInternalScriptPubKeyMan(desc_spk_man),
            is_range ? std::optional(std::make_pair(wallet_descriptor.range_start, wallet_descriptor.range_end)) : std::nullopt,
            wallet_descriptor.next_index
        });
    }

    std::sort(wallet_descriptors.begin(), wallet_descriptors.end(), [](const auto& a, const auto& b) {
        return a.descriptor < b.descriptor;
    });

    UniValue descriptors(UniValue::VARR);
    for (const WalletDescInfo& info : wallet_descriptors) {
        UniValue spk(UniValue::VOBJ);
        spk.pushKV("desc", info.descriptor);
        spk.pushKV("timestamp", info.creation_time);
        spk.pushKV("active", info.active);
        if (info.internal.has_value()) {
            spk.pushKV("internal", info.internal.value());
        }
        if (info.range.has_value()) {
            UniValue range(UniValue::VARR);
            range.push_back(info.range->first);
            range.push_back(info.range->second - 1);
            spk.pushKV("range", std::move(range));
            spk.pushKV("next", info.next_index);
            spk.pushKV("next_index", info.next_index);
        }
        descriptors.push_back(std::move(spk));
    }

    UniValue response(UniValue::VOBJ);
    response.pushKV("wallet_name", wallet.GetName());
    response.pushKV("descriptors", std::move(descriptors));
    return response;
}

static UniValue BuildShieldedAddressListResult(CWallet& wallet)
{
    UniValue result(UniValue::VARR);
    if (!wallet.m_shielded_wallet) return result;

    LOCK2(wallet.cs_wallet, wallet.m_shielded_wallet->cs_shielded);
    const auto addrs = wallet.m_shielded_wallet->GetAddresses();

    for (const auto& addr : addrs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("address", addr.Encode());
        const bool have_spending = wallet.m_shielded_wallet->HaveSpendingKey(addr);
        const bool have_view = wallet.m_shielded_wallet->ExportViewingKey(addr).has_value();
        entry.pushKV("ismine", have_spending);
        entry.pushKV("iswatchonly", have_view && !have_spending);
        result.push_back(std::move(entry));
    }
    return result;
}

static UniValue BuildShieldedTotalBalanceResult(CWallet& wallet, const int minconf = 1)
{
    const Balance transparent_bal = GetBalance(wallet, minconf);
    const CAmount transparent = transparent_bal.m_mine_trusted;

    ShieldedBalanceSummary shielded_summary{};
    bool scan_incomplete{false};
    bool locked_state_incomplete{WalletNeedsLockedShieldedAccountingRefresh(wallet)};
    if (wallet.m_shielded_wallet) {
        LOCK2(wallet.cs_wallet, wallet.m_shielded_wallet->cs_shielded);
        shielded_summary = wallet.m_shielded_wallet->GetShieldedBalanceSummary(minconf);
        scan_incomplete = wallet.m_shielded_wallet->IsScanIncomplete();
    }

    const auto total = CheckedAdd(transparent, shielded_summary.spendable);
    if (!total || !MoneyRange(*total)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("transparent", ValueFromAmount(transparent));
    out.pushKV("shielded", ValueFromAmount(shielded_summary.spendable));
    out.pushKV("total", ValueFromAmount(*total));
    const CAmount transparent_watchonly = transparent_bal.m_watchonly_trusted;
    if (transparent_watchonly != 0 || shielded_summary.watchonly != 0) {
        const auto watchonly_total = CheckedAdd(transparent_watchonly, shielded_summary.watchonly);
        if (!watchonly_total || !MoneyRange(*watchonly_total)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
        }
        const auto total_with_watchonly = CheckedAdd(*total, *watchonly_total);
        if (!total_with_watchonly || !MoneyRange(*total_with_watchonly)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
        }
        out.pushKV("transparent_watchonly", ValueFromAmount(transparent_watchonly));
        out.pushKV("shielded_watchonly", ValueFromAmount(shielded_summary.watchonly));
        out.pushKV("watchonly_total", ValueFromAmount(*watchonly_total));
        out.pushKV("total_including_watchonly", ValueFromAmount(*total_with_watchonly));
    }
    if (scan_incomplete) {
        out.pushKV("scan_incomplete", true);
    }
    if (locked_state_incomplete) {
        out.pushKV("locked_state_incomplete", true);
    }
    return out;
}

static UniValue BuildWalletBalancesResult(const CWallet& wallet)
{
    LOCK(wallet.cs_wallet);

    const auto bal = GetBalance(wallet);
    UniValue balances{UniValue::VOBJ};
    {
        UniValue balances_mine{UniValue::VOBJ};
        balances_mine.pushKV("trusted", ValueFromAmount(bal.m_mine_trusted));
        balances_mine.pushKV("untrusted_pending", ValueFromAmount(bal.m_mine_untrusted_pending));
        balances_mine.pushKV("immature", ValueFromAmount(bal.m_mine_immature));
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            const auto full_bal = GetBalance(wallet, 0, false);
            balances_mine.pushKV("used", ValueFromAmount(full_bal.m_mine_trusted + full_bal.m_mine_untrusted_pending - bal.m_mine_trusted - bal.m_mine_untrusted_pending));
        }
        balances.pushKV("mine", std::move(balances_mine));
    }

    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (spk_man && spk_man->HaveWatchOnly()) {
        UniValue balances_watchonly{UniValue::VOBJ};
        balances_watchonly.pushKV("trusted", ValueFromAmount(bal.m_watchonly_trusted));
        balances_watchonly.pushKV("untrusted_pending", ValueFromAmount(bal.m_watchonly_untrusted_pending));
        balances_watchonly.pushKV("immature", ValueFromAmount(bal.m_watchonly_immature));
        balances.pushKV("watchonly", std::move(balances_watchonly));
    }

    AppendLastProcessedBlock(balances, wallet);
    return balances;
}

static std::vector<RPCResult> WalletIntegrityDoc()
{
    return {
        {RPCResult::Type::NUM, "shielded_keys_total", "Total shielded key records known to the wallet"},
        {RPCResult::Type::NUM, "spending_keys_loaded", "Shielded spending keys currently available"},
        {RPCResult::Type::NUM, "viewing_keys_loaded", "Shielded viewing keys currently available"},
        {RPCResult::Type::NUM, "spending_keys_missing", "Shielded spending keys still missing while viewing data exists"},
        {RPCResult::Type::BOOL, "master_seed_available", "Whether the PQ/shielded master seed is currently available"},
        {RPCResult::Type::NUM, "shielded_notes_total", "Total shielded notes tracked by the wallet"},
        {RPCResult::Type::NUM, "shielded_notes_unspent", "Unspent shielded notes tracked by the wallet"},
        {RPCResult::Type::NUM, "tree_size", "Shielded commitment tree size tracked by the wallet"},
        {RPCResult::Type::NUM, "scan_height", "Last shielded scan height reflected in the wallet state"},
        {RPCResult::Type::BOOL, "scan_incomplete", "Whether the shielded scan is incomplete due to missing historical blocks"},
        {RPCResult::Type::NUM, "pq_descriptors", "Total PQ-aware descriptors tracked by the wallet"},
        {RPCResult::Type::NUM, "pq_descriptors_with_seed", "PQ-aware descriptors with a local seed present"},
        {RPCResult::Type::NUM, "pq_seed_capable_descriptors", "PQ-aware descriptors that can derive local keys"},
        {RPCResult::Type::NUM, "pq_seed_capable_with_seed", "Seed-capable PQ descriptors with a local seed present"},
        {RPCResult::Type::NUM, "pq_public_only_descriptors", "Imported public-only PQ descriptors"},
        {RPCResult::Type::BOOL, "integrity_ok", "Whether the wallet's local key material and scan state look complete"},
        {RPCResult::Type::ARR, "warnings", "Warnings that may affect recoverability or accounting", {
            {RPCResult::Type::STR, "", "Warning message"},
        }},
        {RPCResult::Type::ARR, "notes", "Informational notes about the integrity snapshot", {
            {RPCResult::Type::STR, "", "Informational note"},
        }},
    };
}

static std::vector<RPCResult> WalletBundleManifestDoc()
{
    return {
        {RPCResult::Type::NUM, "created_at", "Unix timestamp when the bundle manifest was created"},
        {RPCResult::Type::STR, "wallet_name", "Wallet name"},
        {RPCResult::Type::STR, "bundle_name", "Logical bundle directory name"},
        {RPCResult::Type::STR, "bundle_dir", "Bundle directory path or logical path stored in the archive"},
        {RPCResult::Type::STR, "backup_file", "Primary backupwallet artifact path or logical path"},
        {RPCResult::Type::BOOL, "include_viewing_keys", "Whether raw shielded viewing keys were exported"},
        {RPCResult::Type::BOOL, "private_descriptors_exported", "Whether private descriptors were exported"},
        {RPCResult::Type::BOOL, "unlocked_by_rpc", "Whether the RPC temporarily unlocked and relocked the wallet"},
        {RPCResult::Type::BOOL, "integrity_ok", "Whether the captured integrity snapshot passed"},
        {RPCResult::Type::ARR, "integrity_warnings", "Warnings from the captured integrity snapshot", {
            {RPCResult::Type::STR, "", "Warning message"},
        }},
        {RPCResult::Type::ARR, "warnings", "Warnings captured while exporting the bundle", {
            {RPCResult::Type::STR, "", "Warning message"},
        }},
    };
}

static std::vector<std::string> UniValueStringArray(const UniValue& value)
{
    std::vector<std::string> out;
    if (!value.isArray()) return out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const UniValue& entry = value[i];
        if (entry.isStr()) out.push_back(entry.get_str());
    }
    return out;
}

static UniValue BuildWalletIntegrityResult(CWallet& wallet)
{
    if (!wallet.m_shielded_wallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Shielded wallet is not initialized");
    }

    wallet.BlockUntilSyncedToCurrentChain();

    UniValue warnings(UniValue::VARR);
    UniValue notes(UniValue::VARR);
    UniValue out(UniValue::VOBJ);

    CShieldedWallet::KeyIntegrityReport report;
    {
        LOCK2(wallet.cs_wallet, wallet.m_shielded_wallet->cs_shielded);
        report = wallet.m_shielded_wallet->VerifyKeyIntegrity();
    }

    out.pushKV("shielded_keys_total", report.total_keys);
    out.pushKV("spending_keys_loaded", report.spending_keys_loaded);
    out.pushKV("viewing_keys_loaded", report.viewing_keys_loaded);
    out.pushKV("spending_keys_missing", report.spending_keys_missing);
    out.pushKV("master_seed_available", report.master_seed_available);
    out.pushKV("shielded_notes_total", report.notes_total);
    out.pushKV("shielded_notes_unspent", report.notes_unspent);
    out.pushKV("tree_size", report.tree_size);
    out.pushKV("scan_height", report.scan_height);
    out.pushKV("scan_incomplete", report.scan_incomplete);

    if (!report.master_seed_available) {
        warnings.push_back("Master seed is not available — spending keys cannot be derived. Wallet may be locked or seed was not persisted.");
    }
    if (report.spending_keys_missing > 0) {
        warnings.push_back(strprintf("%d spending key(s) could not be loaded. Unlock the wallet and retry.", report.spending_keys_missing));
    }
    if (report.scan_incomplete) {
        warnings.push_back("Shielded chain scan is incomplete — some blocks were pruned. Shielded balances may be underreported. Disable pruning and reindex.");
    }

    struct PQDescriptorIntegrityReport {
        int total{0};
        int with_seed{0};
        int seed_capable{0};
        int seed_capable_with_seed{0};
        int public_only{0};
        int missing_local_seed{0};
    };

    const bool private_keys_disabled = wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    PQDescriptorIntegrityReport pq_report;
    {
        LOCK(wallet.cs_wallet);
        WalletBatch batch(wallet.GetDatabase());
        for (const auto& spkm : wallet.GetAllScriptPubKeyMans()) {
            const auto* desc_spkm = dynamic_cast<const DescriptorScriptPubKeyMan*>(spkm);
            if (!desc_spkm) continue;

            std::string desc_str;
            if (!desc_spkm->GetDescriptorString(desc_str, false)) continue;
            if (desc_str.find("pqhd(") == std::string::npos &&
                desc_str.find("mr(") == std::string::npos) continue;

            ++pq_report.total;
            const bool seed_capable = desc_str.find("pqhd(") != std::string::npos;
            if (seed_capable) {
                ++pq_report.seed_capable;
            } else {
                ++pq_report.public_only;
            }

            std::vector<unsigned char> seed;
            if (batch.ReadPQDescriptorSeed(desc_spkm->GetID(), seed) && seed.size() == 32) {
                ++pq_report.with_seed;
                if (seed_capable) {
                    ++pq_report.seed_capable_with_seed;
                }
                memory_cleanse(seed.data(), seed.size());
            } else if (seed_capable) {
                ++pq_report.missing_local_seed;
            }
        }
    }

    out.pushKV("pq_descriptors", pq_report.total);
    out.pushKV("pq_descriptors_with_seed", pq_report.with_seed);
    out.pushKV("pq_seed_capable_descriptors", pq_report.seed_capable);
    out.pushKV("pq_seed_capable_with_seed", pq_report.seed_capable_with_seed);
    out.pushKV("pq_public_only_descriptors", pq_report.public_only);

    if (pq_report.public_only > 0) {
        notes.push_back(strprintf("%d PQ descriptor(s) are public-only and do not require a local seed. This is expected for imported multisig cosigner descriptors.", pq_report.public_only));
    }
    if (pq_report.missing_local_seed > 0) {
        if (private_keys_disabled) {
            notes.push_back(strprintf("%d seed-capable PQ descriptor(s) are missing a local seed because this wallet has private keys disabled.", pq_report.missing_local_seed));
        } else {
            warnings.push_back(strprintf("%d of %d seed-capable PQ descriptor(s) are missing their local seed. These descriptors cannot derive keys and the wallet backup will be incomplete. Use importdescriptors to restore from a private listdescriptors export.",
                                         pq_report.missing_local_seed, pq_report.seed_capable));
        }
    }

    const bool integrity_ok = report.spending_keys_missing == 0 &&
                              report.master_seed_available &&
                              !report.scan_incomplete &&
                              (private_keys_disabled || pq_report.missing_local_seed == 0);
    out.pushKV("integrity_ok", integrity_ok);
    out.pushKV("warnings", std::move(warnings));
    out.pushKV("notes", std::move(notes));
    return out;
}

static bool WalletBundleNeedsUnlock(CWallet& wallet, const bool include_private_descriptors, const bool include_viewing_keys)
{
    if (!wallet.IsCrypted() || !wallet.IsLocked()) {
        return false;
    }

    if (include_private_descriptors &&
        wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) &&
        !wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return true;
    }

    if (!wallet.m_shielded_wallet) {
        return false;
    }

    LOCK2(wallet.cs_wallet, wallet.m_shielded_wallet->cs_shielded);
    if (include_viewing_keys && !wallet.m_shielded_wallet->GetAddresses().empty()) {
        return true;
    }

    return wallet.m_shielded_wallet->LastScannedHeight() >= 0 ||
           !wallet.m_shielded_wallet->GetAddresses().empty();
}

class WalletBundleUnlockSession
{
public:
    WalletBundleUnlockSession(CWallet& wallet, const std::optional<std::string>& passphrase, const bool need_unlock, const std::string& rpc_name)
        : m_wallet(wallet)
    {
        if (!need_unlock) return;

        if (!passphrase.has_value()) {
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                               strprintf("Error: Please enter the wallet passphrase with walletpassphrase first or provide the passphrase to %s.", rpc_name));
        }

        SecureString wallet_pass;
        wallet_pass.reserve(passphrase->size());
        wallet_pass = std::string_view{*passphrase};
        if (wallet_pass.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase cannot be empty");
        }

        LOCK(m_wallet.m_unlock_mutex);
        if (!m_wallet.Unlock(wallet_pass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }

        m_wallet.TopUpKeyPool();
        if (m_wallet.m_shielded_wallet) {
            LOCK(m_wallet.m_shielded_wallet->cs_shielded);
            m_wallet.m_shielded_wallet->MaybeRehydrateSpendingKeys();
        }
        m_unlocked_by_rpc = true;
    }

    ~WalletBundleUnlockSession()
    {
        if (m_unlocked_by_rpc) {
            m_wallet.Lock();
        }
    }

    [[nodiscard]] bool UnlockedByRPC() const
    {
        return m_unlocked_by_rpc;
    }

private:
    CWallet& m_wallet;
    bool m_unlocked_by_rpc{false};
};

struct WalletBundleExportArtifacts
{
    fs::path bundle_dir;
    fs::path backup_path;
    std::vector<std::string> files_written;
    std::vector<std::string> warnings;
    UniValue integrity{UniValue::VOBJ};
    bool unlocked_by_rpc{false};
};

struct WalletBundleArchiveExportArtifacts
{
    DataStream payload_stream{};
    std::vector<std::string> bundle_files;
    std::vector<std::string> warnings;
    UniValue integrity{UniValue::VOBJ};
    bool unlocked_by_rpc{false};
};

class ScopedCleanupDirectory
{
public:
    explicit ScopedCleanupDirectory(fs::path path) : m_path(std::move(path)) {}

    ~ScopedCleanupDirectory()
    {
        CleanupNow();
    }

    const fs::path& Path() const
    {
        return m_path;
    }

    void CleanupNow()
    {
        if (m_path.empty()) return;
        std::error_code ec;
        fs::remove_all(m_path, ec);
        m_path.clear();
    }

private:
    fs::path m_path;
};

static void EnsureParentDirectories(const fs::path& path)
{
    const fs::path parent = path.parent_path();
    if (parent.empty() || fs::exists(parent)) return;
    try {
        if (!fs::create_directories(parent)) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to create destination parent directory %s",
                                                           fs::PathToString(parent)));
        }
    } catch (const fs::filesystem_error& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to create destination parent directory %s: %s",
                                                       fs::PathToString(parent), e.what()));
    }
    SetOwnerOnlyPermissions(parent, /*is_directory=*/true);
}

static void EnsureFreshFileDestination(const fs::path& path)
{
    if (fs::exists(path)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Destination already exists: %s", fs::PathToString(path)));
    }
    EnsureParentDirectories(path);
}

static fs::path CreateUniqueTempFilePath(const fs::path& parent,
                                         const std::string& prefix,
                                         const std::string& suffix = "");

static void WriteBinaryFile(const fs::path& path, Span<const unsigned char> data)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to open %s for writing", fs::PathToString(path)));
    }
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!out.good()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to write %s", fs::PathToString(path)));
    }
    out.close();
    SetOwnerOnlyPermissions(path, /*is_directory=*/false);
}

static void WriteBinaryFileAtomically(const fs::path& path, Span<const unsigned char> data)
{
    EnsureParentDirectories(path);
    const fs::path parent = path.parent_path().empty() ? fs::current_path() : path.parent_path();
    const fs::path temp_path =
        CreateUniqueTempFilePath(parent, fs::PathToString(path.filename()) + ".new");

    FILE* file = fsbridge::fopen(temp_path, "wb");
    if (file == nullptr) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("Failed to open %s for writing", fs::PathToString(temp_path)));
    }
    SetOwnerOnlyPermissions(temp_path, /*is_directory=*/false);

    const auto cleanup_temp = [&]() {
        std::error_code ec;
        fs::remove(temp_path, ec);
    };

    try {
        if (!data.empty() && std::fwrite(data.data(), 1, data.size(), file) != data.size()) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               strprintf("Failed to write %s", fs::PathToString(temp_path)));
        }
        if (!FileCommit(file)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               strprintf("Failed to commit %s", fs::PathToString(temp_path)));
        }
        if (std::fclose(file) != 0) {
            file = nullptr;
            throw JSONRPCError(RPC_WALLET_ERROR,
                               strprintf("Failed to close %s", fs::PathToString(temp_path)));
        }
        file = nullptr;
        if (!RenameOver(temp_path, path)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               strprintf("Failed to rename %s to %s",
                                         fs::PathToString(temp_path),
                                         fs::PathToString(path)));
        }
        SetOwnerOnlyPermissions(path, /*is_directory=*/false);
        DirectoryCommit(parent);
    } catch (...) {
        if (file != nullptr) {
            std::fclose(file);
        }
        cleanup_temp();
        throw;
    }
}

static std::vector<unsigned char> ReadBinaryFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Failed to open %s for reading", fs::PathToString(path)));
    }
    in.seekg(0, std::ios::end);
    const std::streamoff file_size = in.tellg();
    if (file_size < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Failed to read %s", fs::PathToString(path)));
    }
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> data(file_size);
    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), data.size());
        if (!in.good()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Failed to read %s", fs::PathToString(path)));
        }
    }
    return data;
}

static void AddWalletBundleArchivePayloadFile(WalletBundleArchivePayload& payload,
                                              const std::string& relative_path,
                                              std::vector<unsigned char> data)
{
    payload.files.push_back(WalletBundleArchiveFileEntry{relative_path, std::move(data)});
}

static DataStream SerializeWalletBundleArchivePayload(WalletBundleArchivePayload payload,
                                                      std::vector<std::string>* bundle_files_out = nullptr);

static std::string RelativePathString(const fs::path& path)
{
    return fs::PathToString(path);
}

static fs::path CreateUniqueTempDirectory(const fs::path& parent, const std::string& prefix)
{
    EnsureParentDirectories(parent / "placeholder");
    for (int attempt = 0; attempt < 16; ++attempt) {
        const std::string suffix = GetRandHash().GetHex().substr(0, 12);
        const fs::path candidate = parent / fs::u8path(strprintf("%s-%s", prefix, suffix));
        if (fs::exists(candidate)) continue;
        EnsureFreshDirectory(candidate);
        return candidate;
    }
    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to allocate a temporary directory under %s",
                                                   fs::PathToString(parent)));
}

static fs::path CreateUniqueTempFilePath(const fs::path& parent,
                                         const std::string& prefix,
                                         const std::string& suffix)
{
    EnsureParentDirectories(parent / "placeholder");
    for (int attempt = 0; attempt < 16; ++attempt) {
        const std::string random_suffix = GetRandHash().GetHex().substr(0, 12);
        const fs::path candidate = parent / fs::u8path(strprintf("%s-%s%s",
                                                                 prefix,
                                                                 random_suffix,
                                                                 suffix));
        if (!fs::exists(candidate)) return candidate;
    }
    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to allocate a temporary file under %s",
                                                   fs::PathToString(parent)));
}

static fs::path GetWalletBundleArchiveScratchParent(const fs::path& archive_parent)
{
    try {
        return fs::temp_directory_path();
    } catch (const fs::filesystem_error&) {
        return archive_parent;
    }
}

static UniValue BuildWalletBundleManifest(const CWallet& wallet,
                                          const std::string& bundle_ref,
                                          const std::string& backup_ref,
                                          const bool include_viewing_keys,
                                          const bool include_private_descriptors,
                                          const bool unlocked_by_rpc,
                                          const UniValue& integrity,
                                          const std::vector<std::string>& warnings)
{
    UniValue manifest(UniValue::VOBJ);
    manifest.pushKV("created_at", GetTime());
    manifest.pushKV("wallet_name", wallet.GetName());
    manifest.pushKV("bundle_name", WalletBundleDirectoryName(wallet));
    manifest.pushKV("bundle_dir", bundle_ref);
    manifest.pushKV("backup_file", backup_ref);
    manifest.pushKV("include_viewing_keys", include_viewing_keys);
    manifest.pushKV("private_descriptors_exported", include_private_descriptors);
    manifest.pushKV("unlocked_by_rpc", unlocked_by_rpc);
    manifest.pushKV("integrity_ok", integrity["integrity_ok"].get_bool());

    UniValue integrity_warnings(UniValue::VARR);
    for (const auto& warning : UniValueStringArray(integrity.find_value("warnings"))) {
        integrity_warnings.push_back(warning);
    }
    manifest.pushKV("integrity_warnings", std::move(integrity_warnings));

    UniValue manifest_warnings(UniValue::VARR);
    for (const auto& warning : warnings) manifest_warnings.push_back(warning);
    manifest.pushKV("warnings", std::move(manifest_warnings));
    return manifest;
}

static WalletBundleExportArtifacts ExportWalletBundleToDirectory(CWallet& wallet,
                                                                 const fs::path& bundle_dir,
                                                                 const std::optional<std::string>& wallet_passphrase,
                                                                 const bool include_viewing_keys,
                                                                 const std::string& rpc_name,
                                                                 const std::optional<std::string>& manifest_bundle_ref = std::nullopt,
                                                                 const std::optional<std::string>& manifest_backup_ref = std::nullopt)
{
    wallet.BlockUntilSyncedToCurrentChain();
    EnsureViewingKeyBundleExportAllowed(wallet, include_viewing_keys, rpc_name);

    const bool include_private_descriptors =
        wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) &&
        !wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);

    const bool need_unlock = WalletBundleNeedsUnlock(wallet, include_private_descriptors, include_viewing_keys);
    WalletBundleUnlockSession unlock_session(wallet, wallet_passphrase, need_unlock, rpc_name);

    EnsureFreshDirectory(bundle_dir);
    const fs::path key_dir = bundle_dir / "shielded_viewing_keys";
    EnsureFreshDirectory(key_dir);

    WalletBundleExportArtifacts artifacts;
    artifacts.bundle_dir = bundle_dir;
    artifacts.unlocked_by_rpc = unlock_session.UnlockedByRPC();
    const auto note_file = [&](const fs::path& path) {
        artifacts.files_written.push_back(fs::PathToString(fs::absolute(path)));
    };

    artifacts.backup_path = bundle_dir / fs::u8path(WalletBundleBackupFilename(wallet));
    {
        LOCK(wallet.cs_wallet);
        if (!wallet.BackupWallet(fs::PathToString(artifacts.backup_path))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
        }
    }
    SetOwnerOnlyPermissions(artifacts.backup_path, /*is_directory=*/false);
    note_file(artifacts.backup_path);

    artifacts.integrity = BuildWalletIntegrityResult(wallet);
    const UniValue total_balance = BuildShieldedTotalBalanceResult(wallet);
    const UniValue wallet_balances = BuildWalletBalancesResult(wallet);
    const UniValue shielded_addresses = BuildShieldedAddressListResult(wallet);

    const fs::path integrity_path = bundle_dir / "z_verifywalletintegrity.json";
    WriteJsonFile(integrity_path, artifacts.integrity);
    note_file(integrity_path);

    const fs::path balance_path = bundle_dir / "z_gettotalbalance.json";
    WriteJsonFile(balance_path, total_balance);
    note_file(balance_path);

    const fs::path wallet_balances_path = bundle_dir / "getbalances.json";
    WriteJsonFile(wallet_balances_path, wallet_balances);
    note_file(wallet_balances_path);

    const fs::path addresses_path = bundle_dir / "z_listaddresses.json";
    WriteJsonFile(addresses_path, shielded_addresses);
    note_file(addresses_path);

    if (wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        const fs::path public_desc_path = bundle_dir / "listdescriptors_public.json";
        WriteJsonFile(public_desc_path, BuildListDescriptorsResult(wallet, /*priv=*/false));
        note_file(public_desc_path);

        if (include_private_descriptors) {
            const fs::path private_desc_path = bundle_dir / "listdescriptors_private.json";
            WriteJsonFile(private_desc_path, BuildListDescriptorsResult(wallet, /*priv=*/true));
            note_file(private_desc_path);
        }
    }

    WriteTextFile(key_dir / "index.tsv", "");
    note_file(key_dir / "index.tsv");

    if (include_viewing_keys && wallet.m_shielded_wallet) {
        std::vector<std::string> index_lines;
        LOCK2(wallet.cs_wallet, wallet.m_shielded_wallet->cs_shielded);
        const auto addrs = wallet.m_shielded_wallet->GetAddresses();
        for (size_t idx = 0; idx < addrs.size(); ++idx) {
            const ShieldedAddress& addr = addrs[idx];
            auto vk = wallet.m_shielded_wallet->ExportViewingKey(addr);
            if (!vk.has_value()) {
                artifacts.warnings.push_back(strprintf("z_exportviewingkey failed for %s: address not found", addr.Encode()));
                continue;
            }

            mlkem::PublicKey kem_pk;
            if (!wallet.m_shielded_wallet->GetKEMPublicKey(addr, kem_pk)) {
                artifacts.warnings.push_back(strprintf("z_exportviewingkey failed for %s: key material unavailable", addr.Encode()));
                continue;
            }

            const std::string address_text = addr.Encode();
            const uint256 address_hash = Hash(address_text);
            const std::string file_name = strprintf("%d_%s.json", idx + 1, address_hash.GetHex());
            UniValue vk_json(UniValue::VOBJ);
            vk_json.pushKV("address", address_text);
            vk_json.pushKV("viewing_key", HexStr(*vk));
            vk_json.pushKV("kem_public_key", HexStr(kem_pk));

            const fs::path out_path = key_dir / fs::u8path(file_name);
            WriteJsonFile(out_path, vk_json);
            note_file(out_path);
            index_lines.push_back(strprintf("%s\t%s", file_name, address_text));
        }
        WriteTextFile(key_dir / "index.tsv", index_lines.empty() ? "" : util::Join(index_lines, "\n") + "\n");
    }

    const fs::path warnings_path = bundle_dir / "export_warnings.log";
    WriteTextFile(warnings_path, artifacts.warnings.empty() ? "" : util::Join(artifacts.warnings, "\n") + "\n");
    note_file(warnings_path);

    const std::string bundle_ref = manifest_bundle_ref.value_or(fs::PathToString(fs::absolute(bundle_dir)));
    const std::string backup_ref = manifest_backup_ref.value_or(fs::PathToString(fs::absolute(artifacts.backup_path)));
    const fs::path manifest_path = bundle_dir / "manifest.json";
    WriteJsonFile(manifest_path,
                  BuildWalletBundleManifest(wallet, bundle_ref, backup_ref, include_viewing_keys,
                                            include_private_descriptors, artifacts.unlocked_by_rpc,
                                            artifacts.integrity, artifacts.warnings));
    note_file(manifest_path);

    return artifacts;
}

static WalletBundleArchiveExportArtifacts ExportWalletBundleToArchivePayload(
    CWallet& wallet,
    const std::optional<std::string>& wallet_passphrase,
    const bool include_viewing_keys,
    const std::string& rpc_name,
    const std::string& bundle_name,
    const fs::path& archive_parent)
{
    wallet.BlockUntilSyncedToCurrentChain();
    EnsureViewingKeyBundleExportAllowed(wallet, include_viewing_keys, rpc_name);

    const bool include_private_descriptors =
        wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) &&
        !wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    const bool need_unlock = WalletBundleNeedsUnlock(wallet, include_private_descriptors, include_viewing_keys);
    WalletBundleUnlockSession unlock_session(wallet, wallet_passphrase, need_unlock, rpc_name);

    WalletBundleArchiveExportArtifacts artifacts;
    artifacts.unlocked_by_rpc = unlock_session.UnlockedByRPC();

    WalletBundleArchivePayload payload;
    payload.wallet_name = wallet.GetName();
    payload.bundle_name = bundle_name;
    payload.backup_file = WalletBundleBackupFilename(wallet);

    const fs::path temp_root_dir = CreateUniqueTempDirectory(
        GetWalletBundleArchiveScratchParent(archive_parent),
        bundle_name + ".archive");
    ScopedCleanupDirectory cleanup(temp_root_dir);
    const fs::path backup_path = temp_root_dir / fs::u8path(payload.backup_file);
    {
        LOCK(wallet.cs_wallet);
        if (!wallet.BackupWallet(fs::PathToString(backup_path))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
        }
    }
    SetOwnerOnlyPermissions(backup_path, /*is_directory=*/false);
    AddWalletBundleArchivePayloadFile(payload, payload.backup_file, ReadBinaryFile(backup_path));
    std::error_code remove_backup_ec;
    fs::remove(backup_path, remove_backup_ec);
    if (remove_backup_ec) {
        artifacts.warnings.push_back("Temporary plaintext backup file could not be removed immediately after archive staging; verify temporary directories were cleaned after export.");
    }

    artifacts.integrity = BuildWalletIntegrityResult(wallet);
    AddWalletBundleArchivePayloadFile(payload,
                                      "z_verifywalletintegrity.json",
                                      SerializeJsonBytes(artifacts.integrity));
    AddWalletBundleArchivePayloadFile(payload,
                                      "z_gettotalbalance.json",
                                      SerializeJsonBytes(BuildShieldedTotalBalanceResult(wallet)));
    AddWalletBundleArchivePayloadFile(payload,
                                      "getbalances.json",
                                      SerializeJsonBytes(BuildWalletBalancesResult(wallet)));
    AddWalletBundleArchivePayloadFile(payload,
                                      "z_listaddresses.json",
                                      SerializeJsonBytes(BuildShieldedAddressListResult(wallet)));

    if (wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        AddWalletBundleArchivePayloadFile(payload,
                                          "listdescriptors_public.json",
                                          SerializeJsonBytes(BuildListDescriptorsResult(wallet, /*priv=*/false)));
        if (include_private_descriptors) {
            AddWalletBundleArchivePayloadFile(payload,
                                              "listdescriptors_private.json",
                                              SerializeJsonBytes(BuildListDescriptorsResult(wallet, /*priv=*/true)));
        }
    }

    std::vector<std::string> index_lines;
    if (include_viewing_keys && wallet.m_shielded_wallet) {
        LOCK2(wallet.cs_wallet, wallet.m_shielded_wallet->cs_shielded);
        const auto addrs = wallet.m_shielded_wallet->GetAddresses();
        for (size_t idx = 0; idx < addrs.size(); ++idx) {
            const ShieldedAddress& addr = addrs[idx];
            auto vk = wallet.m_shielded_wallet->ExportViewingKey(addr);
            if (!vk.has_value()) {
                artifacts.warnings.push_back(strprintf("z_exportviewingkey failed for %s: address not found", addr.Encode()));
                continue;
            }

            mlkem::PublicKey kem_pk;
            if (!wallet.m_shielded_wallet->GetKEMPublicKey(addr, kem_pk)) {
                artifacts.warnings.push_back(strprintf("z_exportviewingkey failed for %s: key material unavailable", addr.Encode()));
                continue;
            }

            const std::string address_text = addr.Encode();
            const uint256 address_hash = Hash(address_text);
            const std::string file_name = strprintf("shielded_viewing_keys/%d_%s.json", idx + 1, address_hash.GetHex());
            UniValue vk_json(UniValue::VOBJ);
            vk_json.pushKV("address", address_text);
            vk_json.pushKV("viewing_key", HexStr(*vk));
            vk_json.pushKV("kem_public_key", HexStr(kem_pk));
            AddWalletBundleArchivePayloadFile(payload, file_name, SerializeJsonBytes(vk_json));
            index_lines.push_back(strprintf("%s\t%s", fs::PathToString(fs::u8path(file_name).filename()), address_text));
        }
    }
    AddWalletBundleArchivePayloadFile(
        payload,
        "shielded_viewing_keys/index.tsv",
        SerializeTextBytes(index_lines.empty() ? "" : util::Join(index_lines, "\n") + "\n"));
    AddWalletBundleArchivePayloadFile(
        payload,
        "export_warnings.log",
        SerializeTextBytes(artifacts.warnings.empty() ? "" : util::Join(artifacts.warnings, "\n") + "\n"));
    AddWalletBundleArchivePayloadFile(
        payload,
        "manifest.json",
        SerializeJsonBytes(BuildWalletBundleManifest(wallet,
                                                     bundle_name,
                                                     payload.backup_file,
                                                     include_viewing_keys,
                                                     include_private_descriptors,
                                                     artifacts.unlocked_by_rpc,
                                                     artifacts.integrity,
                                                     artifacts.warnings)));

    artifacts.payload_stream = SerializeWalletBundleArchivePayload(std::move(payload), &artifacts.bundle_files);
    return artifacts;
}

static DataStream SerializeWalletBundleArchivePayload(WalletBundleArchivePayload payload,
                                                      std::vector<std::string>* bundle_files_out)
{
    std::sort(payload.files.begin(), payload.files.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.path < rhs.path;
    });
    if (bundle_files_out != nullptr) {
        bundle_files_out->reserve(payload.files.size());
        for (const auto& file : payload.files) {
            bundle_files_out->push_back(file.path);
        }
    }
    DataStream payload_stream{};
    payload_stream << payload;
    return payload_stream;
}

static bool DeriveWalletBundleArchiveKeyIV(const std::string& passphrase,
                                           Span<const unsigned char> salt,
                                           const unsigned int rounds,
                                           unsigned char key[WALLET_CRYPTO_KEY_SIZE],
                                           unsigned char iv[WALLET_CRYPTO_IV_SIZE])
{
    if (passphrase.empty() || rounds < 1 || salt.size() != WALLET_CRYPTO_SALT_SIZE) {
        return false;
    }

    unsigned char buf[CSHA512::OUTPUT_SIZE];
    CSHA512 di;
    di.Write(UCharCast(passphrase.data()), passphrase.size());
    di.Write(salt.data(), salt.size());
    di.Finalize(buf);

    for (unsigned int i = 0; i != rounds - 1; ++i) {
        di.Reset().Write(buf, sizeof(buf)).Finalize(buf);
    }

    memcpy(key, buf, WALLET_CRYPTO_KEY_SIZE);
    memcpy(iv, buf + WALLET_CRYPTO_KEY_SIZE, WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return true;
}

static WalletBundleArchiveEnvelope EncryptWalletBundleArchivePayload(const DataStream& payload_stream, const std::string& archive_passphrase)
{
    if (archive_passphrase.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "archive passphrase cannot be empty");
    }

    const Span<const unsigned char> payload_bytes{UCharCast(payload_stream.data()), payload_stream.size()};
    const uint256 plaintext_sha256 = Hash(payload_bytes);
    WalletBundleArchiveEnvelope envelope;
    envelope.magic = std::string{WALLET_BUNDLE_ARCHIVE_MAGIC};
    envelope.salt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(envelope.salt);
    envelope.plaintext_sha256 = plaintext_sha256;

    unsigned char key[WALLET_CRYPTO_KEY_SIZE];
    unsigned char iv[WALLET_CRYPTO_IV_SIZE];
    if (!DeriveWalletBundleArchiveKeyIV(archive_passphrase, envelope.salt,
                                        envelope.derivation_iterations, key, iv)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive archive encryption key");
    }

    envelope.ciphertext.resize(payload_bytes.size() + AES_BLOCKSIZE);
    AES256CBCEncrypt encryptor(key, iv, /*pad=*/true);
    const int encrypted_len = encryptor.Encrypt(payload_bytes.data(), payload_bytes.size(), envelope.ciphertext.data());
    memory_cleanse(key, sizeof(key));
    memory_cleanse(iv, sizeof(iv));
    if (encrypted_len <= 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to encrypt wallet bundle archive");
    }
    envelope.ciphertext.resize(encrypted_len);
    return envelope;
}

static WalletBundleArchivePayload DecryptWalletBundleArchivePayload(const WalletBundleArchiveEnvelope& envelope, const std::string& archive_passphrase)
{
    if (archive_passphrase.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "archive passphrase cannot be empty");
    }
    if (envelope.magic != WALLET_BUNDLE_ARCHIVE_MAGIC) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Unrecognized wallet bundle archive format");
    }
    if (envelope.version != WALLET_BUNDLE_ARCHIVE_VERSION) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Unsupported wallet bundle archive version %u", envelope.version));
    }
    if (envelope.salt.size() != WALLET_CRYPTO_SALT_SIZE) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive salt is invalid");
    }

    unsigned char key[WALLET_CRYPTO_KEY_SIZE];
    unsigned char iv[WALLET_CRYPTO_IV_SIZE];
    if (!DeriveWalletBundleArchiveKeyIV(archive_passphrase, envelope.salt,
                                        envelope.derivation_iterations, key, iv)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive archive encryption key");
    }

    std::vector<unsigned char> plaintext(envelope.ciphertext.size());
    AES256CBCDecrypt decryptor(key, iv, /*pad=*/true);
    const int decrypted_len = decryptor.Decrypt(envelope.ciphertext.data(), envelope.ciphertext.size(), plaintext.data());
    memory_cleanse(key, sizeof(key));
    memory_cleanse(iv, sizeof(iv));
    if (decrypted_len <= 0) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT,
                           "Error: The wallet bundle archive passphrase entered was incorrect or the archive is corrupt.");
    }
    plaintext.resize(decrypted_len);

    if (Hash(Span<const unsigned char>{plaintext.data(), plaintext.size()}) != envelope.plaintext_sha256) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet bundle archive integrity check failed");
    }

    WalletBundleArchivePayload payload;
    DataStream payload_stream{Span<const unsigned char>{plaintext.data(), plaintext.size()}};
    try {
        payload_stream >> payload;
    } catch (const std::ios_base::failure&) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive payload could not be decoded");
    }
    if (!payload_stream.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive payload has trailing data");
    }
    std::vector<std::string> normalized_paths;
    normalized_paths.reserve(payload.files.size());
    for (auto& file : payload.files) {
        file.path = ValidateWalletBundleArchiveRelativePath(file.path);
        normalized_paths.push_back(file.path);
    }
    EnsureUniqueWalletBundleArchiveRelativePaths(normalized_paths);
    payload.backup_file = ValidateWalletBundleArchiveRelativePath(payload.backup_file);
    return payload;
}

static const std::vector<unsigned char>* FindWalletBundleArchiveFileData(const WalletBundleArchivePayload& payload,
                                                                         const fs::path& relative_path)
{
    const std::string normalized = RelativePathString(relative_path);
    for (const auto& file : payload.files) {
        if (file.path == normalized) {
            return &file.data;
        }
    }
    return nullptr;
}

static UniValue ReadJsonBytes(Span<const unsigned char> bytes, const std::string& label)
{
    const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    UniValue value;
    if (!value.read(text)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to parse wallet bundle archive JSON file %s", label));
    }
    return value;
}

static void ValidateWalletBundleArchiveMetadata(const WalletBundleArchivePayload& payload,
                                                const UniValue& bundled_manifest,
                                                const UniValue& bundled_integrity)
{
    if (!bundled_manifest.isObject()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive manifest is not a JSON object");
    }
    if (!bundled_integrity.isObject()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive integrity snapshot is not a JSON object");
    }

    const UniValue& wallet_name = bundled_manifest["wallet_name"];
    if (!wallet_name.isStr() || wallet_name.get_str() != payload.wallet_name) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive manifest wallet_name does not match the restored backup");
    }
    const UniValue& bundle_name = bundled_manifest["bundle_name"];
    if (!bundle_name.isStr() || bundle_name.get_str() != payload.bundle_name) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive manifest bundle_name does not match the restored backup");
    }
    const UniValue& backup_file = bundled_manifest["backup_file"];
    if (!backup_file.isStr() || backup_file.get_str() != payload.backup_file) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive manifest backup_file does not match the restored backup");
    }
    const UniValue& manifest_integrity_ok = bundled_manifest["integrity_ok"];
    const UniValue& bundled_integrity_ok = bundled_integrity["integrity_ok"];
    if (!manifest_integrity_ok.isBool() || !bundled_integrity_ok.isBool() ||
        manifest_integrity_ok.get_bool() != bundled_integrity_ok.get_bool()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive manifest integrity summary does not match the bundled integrity snapshot");
    }
}

RPCHelpMan importprivkey()
{
    return RPCHelpMan{"importprivkey",
                "\nAdds a private key (as returned by dumpprivkey) to your wallet. Requires a new wallet backup.\n"
                "Hint: use importmulti to import more than one private key.\n"
            "\nNote: This call can take over an hour to complete if rescan is true, during that time, other rpc calls\n"
            "may report that the imported key exists but related transactions are still missing, leading to temporarily incorrect/bogus balances and unspent outputs until rescan completes.\n"
            "The rescan parameter can be set to false if the key was never used to create transactions. If it is set to false,\n"
            "but the key was used to create transactions, rescanblockchain needs to be called with the appropriate block range.\n"
            "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
            "Note: This command is only compatible with legacy wallets. Use \"importdescriptors\" with \"combo(X)\" for descriptor wallets.\n",
                {
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key (see dumpprivkey)"},
                    {"label", RPCArg::Type::STR, RPCArg::DefaultHint{"current label if address exists, otherwise \"\""}, "An optional label"},
                    {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true}, "Scan the chain and mempool for wallet transactions."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nImport using default blank label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
    }

    EnsureLegacyScriptPubKeyMan(*pwallet, true);

    WalletRescanReserver reserver(*pwallet);
    bool fRescan = true;
    {
        LOCK(pwallet->cs_wallet);

        EnsureWalletIsUnlocked(*pwallet);

        std::string strSecret = request.params[0].get_str();
        const std::string strLabel{LabelFromValue(request.params[1])};

        // Whether to perform rescan after import
        if (!request.params[2].isNull())
            fRescan = request.params[2].get_bool();

        if (fRescan && pwallet->chain().havePruned()) {
            // Exit early and print an error.
            // If a block is pruned after this check, we will import the key(s),
            // but fail the rescan with a generic error.
            throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled when blocks are pruned");
        }

        if (fRescan && !reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
        }

        CKey key = DecodeSecret(strSecret);
        if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

        CPubKey pubkey = key.GetPubKey();
        CHECK_NONFATAL(key.VerifyPubKey(pubkey));
        CKeyID vchAddress = pubkey.GetID();
        {
            pwallet->MarkDirty();

            // We don't know which corresponding address will be used;
            // label all new addresses, and label existing addresses if a
            // label was passed.
            for (const auto& dest : GetAllDestinationsForKey(pubkey)) {
                if (!request.params[1].isNull() || !pwallet->FindAddressBookEntry(dest)) {
                    pwallet->SetAddressBook(dest, strLabel, AddressPurpose::RECEIVE);
                }
            }

            // Use timestamp of 1 to scan the whole chain
            if (!pwallet->ImportPrivKeys({{vchAddress, key}}, 1)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
            }

            // Add the wpkh script for this key if possible
            if (pubkey.IsCompressed()) {
                pwallet->ImportScripts({GetScriptForDestination(WitnessV0KeyHash(vchAddress))}, /*timestamp=*/0);
            }
        }
    }
    if (fRescan) {
        RescanWallet(*pwallet, reserver);
    }

    return UniValue::VNULL;
},
    };
}

UniValue ProcessDescriptorImport(CWallet& wallet, const UniValue& data, const int64_t timestamp, const std::vector<CExtKey>& master_keys = {}) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

RPCHelpMan importaddress()
{
    return RPCHelpMan{"importaddress",
            "\nAdds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend. Requires a new wallet backup.\n"
            "\nNote: This call can take over an hour to complete if rescan is true, during that time, other rpc calls\n"
            "may report that the imported address exists but related transactions are still missing, leading to temporarily incorrect/bogus balances and unspent outputs until rescan completes.\n"
            "The rescan parameter can be set to false if the key was never used to create transactions. If it is set to false,\n"
            "but the key was used to create transactions, rescanblockchain needs to be called with the appropriate block range.\n"
            "If you have the full public key, you should call importpubkey instead of this.\n"
            "Hint: use importmulti to import more than one address.\n"
            "\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
            "as change, and not show up in many RPCs.\n"
            "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
            "Note: For descriptor wallets, this command will create new descriptor/s, and only works if the wallet has private keys disabled.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BTX address (or hex-encoded script)"},
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "An optional label"},
                    {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true}, "Scan the chain and mempool for wallet transactions."},
                    {"p2sh", RPCArg::Type::BOOL, RPCArg::Default{false}, "Add the P2SH version of the script as well"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nImport an address with rescan\n"
            + HelpExampleCli("importaddress", "\"myaddress\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myaddress\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myaddress\", \"testing\", false")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Use legacy spkm only if the wallet does not support descriptors.
    bool use_legacy = !pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS);
    if (use_legacy) {
        // In case the wallet is blank
    EnsureLegacyScriptPubKeyMan(*pwallet, true);
    } else {
        // We don't allow mixing watch-only descriptors with spendable ones.
        if (!pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import address in wallet with private keys enabled. "
                                                 "Create wallet with no private keys to watch specific addresses/scripts");
        }
    }

    const std::string strLabel{LabelFromValue(request.params[1])};

    // Whether to perform rescan after import
    bool fRescan = true;
    if (!request.params[2].isNull())
        fRescan = request.params[2].get_bool();

    if (fRescan && pwallet->chain().havePruned()) {
        // Exit early and print an error.
        // If a block is pruned after this check, we will import the key(s),
        // but fail the rescan with a generic error.
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled when blocks are pruned");
    }

    WalletRescanReserver reserver(*pwallet);
    if (fRescan && !reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (!request.params[3].isNull())
        fP2SH = request.params[3].get_bool();

    // Import descriptor helper function
    const auto& import_descriptor = [pwallet](const std::string& desc, const std::string label) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        UniValue data(UniValue::VType::VOBJ);
        data.pushKV("desc", AddChecksum(desc));
        if (!label.empty()) data.pushKV("label", label);
        const UniValue& ret = ProcessDescriptorImport(*pwallet, data, /*timestamp=*/1);
        if (ret.exists("error")) throw ret["error"];
    };

    {
        LOCK(pwallet->cs_wallet);

        const std::string& address = request.params[0].get_str();
        CTxDestination dest = DecodeDestination(address);
        if (IsValidDestination(dest)) {
            if (fP2SH) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
            }
            if (OutputTypeFromDestination(dest) == OutputType::BECH32M) {
                if (use_legacy)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bech32m addresses cannot be imported into legacy wallets");
            }

            pwallet->MarkDirty();

            if (use_legacy) {
            pwallet->ImportScriptPubKeys(strLabel, {GetScriptForDestination(dest)}, /*have_solving_data=*/false, /*apply_label=*/true, /*timestamp=*/1);
            } else {
                import_descriptor("addr(" + address + ")", strLabel);
            }
        } else if (IsHex(request.params[0].get_str())) {
            const std::string& hex = request.params[0].get_str();

            if (use_legacy) {
                std::vector<unsigned char> data(ParseHex(hex));
            CScript redeem_script(data.begin(), data.end());

            std::set<CScript> scripts = {redeem_script};
            pwallet->ImportScripts(scripts, /*timestamp=*/0);

            if (fP2SH) {
                scripts.insert(GetScriptForDestination(ScriptHash(redeem_script)));
            }

            pwallet->ImportScriptPubKeys(strLabel, scripts, /*have_solving_data=*/false, /*apply_label=*/true, /*timestamp=*/1);
            } else {
                // P2SH Not allowed. Can't detect inner P2SH function from a raw hex.
                if (fP2SH) throw JSONRPCError(RPC_WALLET_ERROR, "P2SH import feature disabled for descriptors' wallet. "
                                                                "Use 'importdescriptors' to specify inner P2SH function");

                // Import descriptors
                import_descriptor("raw(" + hex + ")", strLabel);
            }
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BTX address or script");
        }
    }
    if (fRescan)
    {
        RescanWallet(*pwallet, reserver);
        pwallet->ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan importprunedfunds()
{
    return RPCHelpMan{"importprunedfunds",
                "\nImports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n",
                {
                    {"rawtransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A raw transaction in hex funding an already-existing address in wallet"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex output from gettxoutproof that contains the transaction"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }
    uint256 hashTx = tx.GetHash();

    DataStream ssMB{ParseHexV(request.params[1], "proof")};
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    std::vector<uint256> vMatch;
    std::vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Something wrong with merkleblock");
    }

    LOCK(pwallet->cs_wallet);
    int height;
    if (!pwallet->chain().findAncestorByHash(pwallet->GetLastBlockHash(), merkleBlock.header.GetHash(), FoundBlock().height(height))) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
    }

    std::vector<uint256>::const_iterator it;
    if ((it = std::find(vMatch.begin(), vMatch.end(), hashTx)) == vMatch.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction given doesn't exist in proof");
    }

    unsigned int txnIndex = vIndex[it - vMatch.begin()];

    CTransactionRef tx_ref = MakeTransactionRef(tx);
    if (pwallet->IsMine(*tx_ref)) {
        pwallet->AddToWallet(std::move(tx_ref), TxStateConfirmed{merkleBlock.header.GetHash(), height, static_cast<int>(txnIndex)});
        return UniValue::VNULL;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
},
    };
}

RPCHelpMan removeprunedfunds()
{
    return RPCHelpMan{"removeprunedfunds",
                "\nDeletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will affect wallet balances.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded id of the transaction you are deleting"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    std::vector<uint256> vHash;
    vHash.push_back(hash);
    if (auto res = pwallet->RemoveTxs(vHash); !res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan importpubkey()
{
    return RPCHelpMan{"importpubkey",
                "\nAdds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend. Requires a new wallet backup.\n"
                "Hint: use importmulti to import more than one public key.\n"
            "\nNote: This call can take over an hour to complete if rescan is true, during that time, other rpc calls\n"
            "may report that the imported pubkey exists but related transactions are still missing, leading to temporarily incorrect/bogus balances and unspent outputs until rescan completes.\n"
            "The rescan parameter can be set to false if the key was never used to create transactions. If it is set to false,\n"
            "but the key was used to create transactions, rescanblockchain needs to be called with the appropriate block range.\n"
            "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
            "Note: This command is only compatible with legacy wallets. Use \"importdescriptors\" with \"combo(X)\" for descriptor wallets.\n",
                {
                    {"pubkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The hex-encoded public key"},
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "An optional label"},
                    {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true}, "Scan the chain and mempool for wallet transactions."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nImport a public key with rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importpubkey", "\"mypubkey\", \"testing\", false")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    EnsureLegacyScriptPubKeyMan(*pwallet, true);

    const std::string strLabel{LabelFromValue(request.params[1])};

    // Whether to perform rescan after import
    bool fRescan = true;
    if (!request.params[2].isNull())
        fRescan = request.params[2].get_bool();

    if (fRescan && pwallet->chain().havePruned()) {
        // Exit early and print an error.
        // If a block is pruned after this check, we will import the key(s),
        // but fail the rescan with a generic error.
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled when blocks are pruned");
    }

    WalletRescanReserver reserver(*pwallet);
    if (fRescan && !reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    CPubKey pubKey = HexToPubKey(request.params[0].get_str());

    {
        LOCK(pwallet->cs_wallet);

        std::set<CScript> script_pub_keys;
        for (const auto& dest : GetAllDestinationsForKey(pubKey)) {
            script_pub_keys.insert(GetScriptForDestination(dest));
        }

        pwallet->MarkDirty();

        pwallet->ImportScriptPubKeys(strLabel, script_pub_keys, /*have_solving_data=*/true, /*apply_label=*/true, /*timestamp=*/1);

        pwallet->ImportPubKeys({{pubKey.GetID(), false}}, {{pubKey.GetID(), pubKey}} , /*key_origins=*/{}, /*add_keypool=*/false, /*timestamp=*/1);
    }
    if (fRescan)
    {
        RescanWallet(*pwallet, reserver);
        pwallet->ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);
    }

    return UniValue::VNULL;
},
    };
}


RPCHelpMan importwallet()
{
    return RPCHelpMan{"importwallet",
                "\nImports keys from a wallet dump file (see dumpwallet). Requires a new wallet backup to include imported keys.\n"
                "Note: Blockchain and Mempool will be rescanned after a successful import. Use \"getwalletinfo\" to query the scanning progress.\n"
                "Note: This command is only compatible with legacy wallets.\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet file"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"test\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"test\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"test\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    EnsureLegacyScriptPubKeyMan(*pwallet, true);

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int64_t nTimeBegin = 0;
    bool fGood = true;
    {
        LOCK(pwallet->cs_wallet);

        EnsureWalletIsUnlocked(*pwallet);

        std::ifstream file;
        file.open(fs::u8path(request.params[0].get_str()), std::ios::in | std::ios::ate);
        if (!file.is_open()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");
        }
        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(nTimeBegin)));

        int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
        file.seekg(0, file.beg);

        // Use uiInterface.ShowProgress instead of pwallet.ShowProgress because pwallet.ShowProgress has a cancel button tied to AbortRescan which
        // we don't want for this progress bar showing the import progress. uiInterface.ShowProgress does not have a cancel button.
        pwallet->chain().showProgress(strprintf("%s %s", pwallet->GetDisplayName(), _("Importing…")), 0, false); // show progress dialog in GUI
        std::vector<std::tuple<CKey, int64_t, bool, std::string>> keys;
        std::vector<std::pair<CScript, int64_t>> scripts;
        while (file.good()) {
            pwallet->chain().showProgress("", std::max(1, std::min(50, (int)(((double)file.tellg() / (double)nFilesize) * 100))), false);
            std::string line;
            std::getline(file, line);
            if (line.empty() || line[0] == '#')
                continue;

            std::vector<std::string> vstr = SplitString(line, ' ');
            if (vstr.size() < 2)
                continue;
            CKey key = DecodeSecret(vstr[0]);
            if (key.IsValid()) {
                int64_t nTime{ParseISO8601DateTime(vstr[1]).value_or(0)};
                std::string strLabel;
                bool fLabel = true;
                for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
                    if (vstr[nStr].front() == '#')
                        break;
                    if (vstr[nStr] == "change=1")
                        fLabel = false;
                    if (vstr[nStr] == "reserve=1")
                        fLabel = false;
                    if (vstr[nStr].substr(0,6) == "label=") {
                        strLabel = DecodeDumpString(vstr[nStr].substr(6));
                        fLabel = true;
                    }
                }
                nTimeBegin = std::min(nTimeBegin, nTime);
                keys.emplace_back(key, nTime, fLabel, strLabel);
            } else if(IsHex(vstr[0])) {
                std::vector<unsigned char> vData(ParseHex(vstr[0]));
                CScript script = CScript(vData.begin(), vData.end());
                int64_t birth_time{ParseISO8601DateTime(vstr[1]).value_or(0)};
                if (birth_time > 0) nTimeBegin = std::min(nTimeBegin, birth_time);
                scripts.emplace_back(script, birth_time);
            }
        }
        file.close();
        EnsureBlockDataFromTime(*pwallet, nTimeBegin);
        // We now know whether we are importing private keys, so we can error if private keys are disabled
        if (keys.size() > 0 && pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            pwallet->chain().showProgress("", 100, false); // hide progress dialog in GUI
            throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled when private keys are disabled");
        }
        double total = (double)(keys.size() + scripts.size());
        double progress = 0;
        for (const auto& key_tuple : keys) {
            pwallet->chain().showProgress("", std::max(50, std::min(75, (int)((progress / total) * 100) + 50)), false);
            const CKey& key = std::get<0>(key_tuple);
            int64_t time = std::get<1>(key_tuple);
            bool has_label = std::get<2>(key_tuple);
            std::string label = std::get<3>(key_tuple);

            CPubKey pubkey = key.GetPubKey();
            CHECK_NONFATAL(key.VerifyPubKey(pubkey));
            CKeyID keyid = pubkey.GetID();

            pwallet->WalletLogPrintf("Importing %s...\n", EncodeDestination(PKHash(keyid)));

            if (!pwallet->ImportPrivKeys({{keyid, key}}, time)) {
                pwallet->WalletLogPrintf("Error importing key for %s\n", EncodeDestination(PKHash(keyid)));
                fGood = false;
                continue;
            }

            if (has_label)
                pwallet->SetAddressBook(PKHash(keyid), label, AddressPurpose::RECEIVE);
            progress++;
        }
        for (const auto& script_pair : scripts) {
            pwallet->chain().showProgress("", std::max(50, std::min(75, (int)((progress / total) * 100) + 50)), false);
            const CScript& script = script_pair.first;
            int64_t time = script_pair.second;

            if (!pwallet->ImportScripts({script}, time)) {
                pwallet->WalletLogPrintf("Error importing script %s\n", HexStr(script));
                fGood = false;
                continue;
            }

            progress++;
        }
        pwallet->chain().showProgress("", 100, false); // hide progress dialog in GUI
    }
    pwallet->chain().showProgress("", 100, false); // hide progress dialog in GUI
    RescanWallet(*pwallet, reserver, nTimeBegin, /*update=*/false);
    pwallet->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys/scripts to wallet");

    return UniValue::VNULL;
},
    };
}

RPCHelpMan dumpprivkey()
{
    return RPCHelpMan{"dumpprivkey",
                "\nReveals the private key corresponding to 'address'.\n"
                "Then the importprivkey can be used with this output\n"
                "Note: This command is only compatible with legacy wallets.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BTX address for the private key"},
                },
                RPCResult{
                    RPCResult::Type::STR, "key", "The private key"
                },
                RPCExamples{
                    HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const LegacyScriptPubKeyMan& spk_man = EnsureConstLegacyScriptPubKeyMan(*pwallet);

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    EnsureWalletIsUnlocked(*pwallet);

    std::string strAddress = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BTX address");
    }
    auto keyid = GetKeyForDestination(spk_man, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CKey vchSecret;
    if (!spk_man.GetKey(keyid, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    return EncodeSecret(vchSecret);
},
    };
}

RPCHelpMan dumpmasterprivkey()
{
    return RPCHelpMan{"dumpmasterprivkey",
                "Reveals the current master private key.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR, "key", "The HD master private key"
                },
                RPCExamples{
                    HelpExampleCli("dumpmasterprivkey", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*wallet);

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    EnsureWalletIsUnlocked(*pwallet);

    CKeyID seed_id = spk_man.GetHDChain().seed_id;
    if (!spk_man.IsHDEnabled()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not a HD wallet.");
    }
    CKey seed;
    if (spk_man.GetKey(seed_id, seed)) {
        CExtKey masterKey;
        masterKey.SetSeed(seed);

        return EncodeExtKey(masterKey);
    } else {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to retrieve HD master private key");
        return NullUniValue;
    }
},
    };
}


RPCHelpMan dumpwallet()
{
    return RPCHelpMan{"dumpwallet",
                "\nDumps all wallet keys in a human-readable format to a server-side file. This does not allow overwriting existing files.\n"
                "Imported scripts are included in the dumpfile, but corresponding BIP173 addresses, etc. may not be added automatically by importwallet.\n"
                "Note that if your wallet contains keys which are not derived from your HD seed (e.g. imported keys), these are not covered by\n"
                "only backing up the seed itself, and must be backed up too (e.g. ensure you back up the whole dumpfile).\n"
                "Note: This command is only compatible with legacy wallets.\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The filename with path (absolute path recommended)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "filename", "The filename with full absolute path"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CWallet& wallet = *pwallet;
    const LegacyScriptPubKeyMan& spk_man = EnsureConstLegacyScriptPubKeyMan(wallet);

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);

    EnsureWalletIsUnlocked(wallet);

    fs::path filepath = fs::u8path(request.params[0].get_str());
    filepath = fs::absolute(filepath);

    /* Prevent arbitrary files from being overwritten. There have been reports
     * that users have overwritten wallet files this way:
     * https://github.com/bitcoin/bitcoin/issues/9934
     * It may also avoid other security issues.
     */
    if (fs::exists(filepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, filepath.utf8string() + " already exists. If you are sure this is what you want, move it out of the way first");
    }

    std::ofstream file;
    file.open(filepath);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64_t> mapKeyBirth;
    wallet.GetKeyBirthTimes(mapKeyBirth);

    int64_t block_time = 0;
    CHECK_NONFATAL(wallet.chain().findBlock(wallet.GetLastBlockHash(), FoundBlock().time(block_time)));

    // Note: To avoid a lock order issue, access to cs_main must be locked before cs_KeyStore.
    // So we do the two things in this function that lock cs_main first: GetKeyBirthTimes, and findBlock.
    LOCK(spk_man.cs_KeyStore);

    const std::map<CKeyID, int64_t>& mapKeyPool = spk_man.GetAllReserveKeys();
    std::set<CScriptID> scripts = spk_man.GetCScripts();

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    vKeyBirth.reserve(mapKeyBirth.size());
    for (const auto& entry : mapKeyBirth) {
        vKeyBirth.emplace_back(entry.second, entry.first);
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by %s %s\n", CLIENT_NAME, FormatFullVersion());
    file << strprintf("# * Created on %s\n", FormatISO8601DateTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", wallet.GetLastBlockHeight(), wallet.GetLastBlockHash().ToString());
    file << strprintf("#   mined on %s\n", FormatISO8601DateTime(block_time));
    file << "\n";

    // add the base58check encoded extended master if the wallet uses HD
    CKeyID seed_id = spk_man.GetHDChain().seed_id;
    if (!seed_id.IsNull())
    {
        CKey seed;
        if (spk_man.GetKey(seed_id, seed)) {
            CExtKey masterKey;
            masterKey.SetSeed(seed);

            file << "# extended private masterkey: " << EncodeExtKey(masterKey) << "\n\n";
        }
    }
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = FormatISO8601DateTime(it->first);
        std::string strAddr;
        std::string strLabel;
        CKey key;
        if (spk_man.GetKey(keyid, key)) {
            CKeyMetadata metadata;
            const auto it{spk_man.mapKeyMetadata.find(keyid)};
            if (it != spk_man.mapKeyMetadata.end()) metadata = it->second;
            file << strprintf("%s %s ", EncodeSecret(key), strTime);
            if (GetWalletAddressesForKey(&spk_man, wallet, keyid, strAddr, strLabel)) {
                file << strprintf("label=%s", strLabel);
            } else if (keyid == seed_id) {
                file << "hdseed=1";
            } else if (mapKeyPool.count(keyid)) {
                file << "reserve=1";
            } else if (metadata.hdKeypath == "s") {
                file << "inactivehdseed=1";
            } else {
                file << "change=1";
            }
            if (metadata.has_key_origin) {
                file << " hdkeypath=" + WriteHDKeypath(metadata.key_origin.path, /*apostrophe=*/true);
                if (!(metadata.hd_seed_id.IsNull() || (metadata.hdKeypath == "s" && metadata.hd_seed_id == keyid))) {
                    file << " hdseedid=" + metadata.hd_seed_id.GetHex();
                }
            }
            file << strprintf(" # addr=%s\n", strAddr);
        }
    }
    file << "\n";
    for (const CScriptID &scriptid : scripts) {
        CScript script;
        std::string create_time = "0";
        std::string address = EncodeDestination(ScriptHash(scriptid));
        // get birth times for scripts with metadata
        auto it = spk_man.m_script_metadata.find(scriptid);
        if (it != spk_man.m_script_metadata.end()) {
            create_time = FormatISO8601DateTime(it->second.nCreateTime);
        }
        if(spk_man.GetCScript(scriptid, script)) {
            file << strprintf("%s %s script=1", HexStr(script), create_time);
            file << strprintf(" # addr=%s\n", address);
        }
    }
    file << "\n";
    file << "# End of dump\n";
    file.close();

    UniValue reply(UniValue::VOBJ);
    reply.pushKV("filename", filepath.utf8string());

    return reply;
},
    };
}

struct ImportData
{
    // Input data
    std::unique_ptr<CScript> redeemscript; //!< Provided redeemScript; will be moved to `import_scripts` if relevant.
    std::unique_ptr<CScript> witnessscript; //!< Provided witnessScript; will be moved to `import_scripts` if relevant.

    // Output data
    std::set<CScript> import_scripts;
    std::map<CKeyID, bool> used_keys; //!< Import these private keys if available (the value indicates whether if the key is required for solvability)
    std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>> key_origins;
};

enum class ScriptContext
{
    TOP, //!< Top-level scriptPubKey
    P2SH, //!< P2SH redeemScript
    WITNESS_V0, //!< P2WSH witnessScript
};

// Analyse the provided scriptPubKey, determining which keys and which redeem scripts from the ImportData struct are needed to spend it, and mark them as used.
// Returns an error string, or the empty string for success.
// NOLINTNEXTLINE(misc-no-recursion)
static std::string RecurseImportData(const CScript& script, ImportData& import_data, const ScriptContext script_ctx)
{
    // Use Solver to obtain script type and parsed pubkeys or hashes:
    std::vector<std::vector<unsigned char>> solverdata;
    TxoutType script_type = Solver(script, solverdata);

    switch (script_type) {
    case TxoutType::PUBKEY: {
        CPubKey pubkey(solverdata[0]);
        import_data.used_keys.emplace(pubkey.GetID(), false);
        return "";
    }
    case TxoutType::PUBKEYHASH: {
        CKeyID id = CKeyID(uint160(solverdata[0]));
        import_data.used_keys[id] = true;
        return "";
    }
    case TxoutType::SCRIPTHASH: {
        if (script_ctx == ScriptContext::P2SH) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Trying to nest P2SH inside another P2SH");
        if (script_ctx == ScriptContext::WITNESS_V0) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Trying to nest P2SH inside a P2WSH");
        CHECK_NONFATAL(script_ctx == ScriptContext::TOP);
        CScriptID id = CScriptID(uint160(solverdata[0]));
        auto subscript = std::move(import_data.redeemscript); // Remove redeemscript from import_data to check for superfluous script later.
        if (!subscript) return "missing redeemscript";
        if (CScriptID(*subscript) != id) return "redeemScript does not match the scriptPubKey";
        import_data.import_scripts.emplace(*subscript);
        return RecurseImportData(*subscript, import_data, ScriptContext::P2SH);
    }
    case TxoutType::MULTISIG: {
        for (size_t i = 1; i + 1< solverdata.size(); ++i) {
            CPubKey pubkey(solverdata[i]);
            import_data.used_keys.emplace(pubkey.GetID(), false);
        }
        return "";
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH: {
        if (script_ctx == ScriptContext::WITNESS_V0) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Trying to nest P2WSH inside another P2WSH");
        CScriptID id{RIPEMD160(solverdata[0])};
        auto subscript = std::move(import_data.witnessscript); // Remove redeemscript from import_data to check for superfluous script later.
        if (!subscript) return "missing witnessscript";
        if (CScriptID(*subscript) != id) return "witnessScript does not match the scriptPubKey or redeemScript";
        if (script_ctx == ScriptContext::TOP) {
            import_data.import_scripts.emplace(script); // Special rule for IsMine: native P2WSH requires the TOP script imported (see script/ismine.cpp)
        }
        import_data.import_scripts.emplace(*subscript);
        return RecurseImportData(*subscript, import_data, ScriptContext::WITNESS_V0);
    }
    case TxoutType::WITNESS_V0_KEYHASH: {
        if (script_ctx == ScriptContext::WITNESS_V0) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Trying to nest P2WPKH inside P2WSH");
        CKeyID id = CKeyID(uint160(solverdata[0]));
        import_data.used_keys[id] = true;
        if (script_ctx == ScriptContext::TOP) {
            import_data.import_scripts.emplace(script); // Special rule for IsMine: native P2WPKH requires the TOP script imported (see script/ismine.cpp)
        }
        return "";
    }
    case TxoutType::NULL_DATA:
        return "unspendable script";
    case TxoutType::NONSTANDARD:
    case TxoutType::WITNESS_UNKNOWN:
    case TxoutType::WITNESS_V1_TAPROOT:
    case TxoutType::WITNESS_V2_P2MR:
    case TxoutType::ANCHOR:
        return "unrecognized script";
    } // no default case, so the compiler can warn about missing cases
    NONFATAL_UNREACHABLE();
}

static UniValue ProcessImportLegacy(ImportData& import_data, std::map<CKeyID, CPubKey>& pubkey_map, std::map<CKeyID, CKey>& privkey_map, std::set<CScript>& script_pub_keys, bool& have_solving_data, const UniValue& data, std::vector<std::pair<CKeyID, bool>>& ordered_pubkeys)
{
    UniValue warnings(UniValue::VARR);

    // First ensure scriptPubKey has either a script or JSON with "address" string
    const UniValue& scriptPubKey = data["scriptPubKey"];
    bool isScript = scriptPubKey.getType() == UniValue::VSTR;
    if (!isScript && !(scriptPubKey.getType() == UniValue::VOBJ && scriptPubKey.exists("address"))) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "scriptPubKey must be string with script or JSON with address string");
    }
    const std::string& output = isScript ? scriptPubKey.get_str() : scriptPubKey["address"].get_str();

    // Optional fields.
    const std::string& strRedeemScript = data.exists("redeemscript") ? data["redeemscript"].get_str() : "";
    const std::string& witness_script_hex = data.exists("witnessscript") ? data["witnessscript"].get_str() : "";
    const UniValue& pubKeys = data.exists("pubkeys") ? data["pubkeys"].get_array() : UniValue();
    const UniValue& keys = data.exists("keys") ? data["keys"].get_array() : UniValue();
    const bool internal = data.exists("internal") ? data["internal"].get_bool() : false;
    const bool watchOnly = data.exists("watchonly") ? data["watchonly"].get_bool() : false;

    if (data.exists("range")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for a non-descriptor import");
    }

    // Generate the script and destination for the scriptPubKey provided
    CScript script;
    if (!isScript) {
        CTxDestination dest = DecodeDestination(output);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address \"" + output + "\"");
        }
        if (OutputTypeFromDestination(dest) == OutputType::BECH32M) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bech32m addresses cannot be imported into legacy wallets");
        }
        script = GetScriptForDestination(dest);
    } else {
        if (!IsHex(output)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid scriptPubKey \"" + output + "\"");
        }
        std::vector<unsigned char> vData(ParseHex(output));
        script = CScript(vData.begin(), vData.end());
        CTxDestination dest;
        if (!ExtractDestination(script, dest) && !internal) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal must be set to true for nonstandard scriptPubKey imports.");
        }
    }
    script_pub_keys.emplace(script);

    // Parse all arguments
    if (strRedeemScript.size()) {
        if (!IsHex(strRedeemScript)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid redeem script \"" + strRedeemScript + "\": must be hex string");
        }
        auto parsed_redeemscript = ParseHex(strRedeemScript);
        import_data.redeemscript = std::make_unique<CScript>(parsed_redeemscript.begin(), parsed_redeemscript.end());
    }
    if (witness_script_hex.size()) {
        if (!IsHex(witness_script_hex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid witness script \"" + witness_script_hex + "\": must be hex string");
        }
        auto parsed_witnessscript = ParseHex(witness_script_hex);
        import_data.witnessscript = std::make_unique<CScript>(parsed_witnessscript.begin(), parsed_witnessscript.end());
    }
    for (size_t i = 0; i < pubKeys.size(); ++i) {
        CPubKey pubkey = HexToPubKey(pubKeys[i].get_str());
        pubkey_map.emplace(pubkey.GetID(), pubkey);
        ordered_pubkeys.emplace_back(pubkey.GetID(), internal);
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        const auto& str = keys[i].get_str();
        CKey key = DecodeSecret(str);
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");
        }
        CPubKey pubkey = key.GetPubKey();
        CKeyID id = pubkey.GetID();
        if (pubkey_map.count(id)) {
            pubkey_map.erase(id);
        }
        privkey_map.emplace(id, key);
    }


    // Verify and process input data
    have_solving_data = import_data.redeemscript || import_data.witnessscript || pubkey_map.size() || privkey_map.size();
    if (have_solving_data) {
        // Match up data in import_data with the scriptPubKey in script.
        auto error = RecurseImportData(script, import_data, ScriptContext::TOP);

        // Verify whether the watchonly option corresponds to the availability of private keys.
        bool spendable = std::all_of(import_data.used_keys.begin(), import_data.used_keys.end(), [&](const std::pair<CKeyID, bool>& used_key){ return privkey_map.count(used_key.first) > 0; });
        if (!watchOnly && !spendable) {
            warnings.push_back("Some private keys are missing, outputs will be considered watchonly. If this is intentional, specify the watchonly flag.");
        }
        if (watchOnly && spendable) {
            warnings.push_back("All private keys are provided, outputs will be considered spendable. If this is intentional, do not specify the watchonly flag.");
        }

        // Check that all required keys for solvability are provided.
        if (error.empty()) {
            for (const auto& require_key : import_data.used_keys) {
                if (!require_key.second) continue; // Not a required key
                if (pubkey_map.count(require_key.first) == 0 && privkey_map.count(require_key.first) == 0) {
                    error = "some required keys are missing";
                }
            }
        }

        if (!error.empty()) {
            warnings.push_back("Importing as non-solvable: " + error + ". If this is intentional, don't provide any keys, pubkeys, witnessscript, or redeemscript.");
            import_data = ImportData();
            pubkey_map.clear();
            privkey_map.clear();
            have_solving_data = false;
        } else {
            // RecurseImportData() removes any relevant redeemscript/witnessscript from import_data, so we can use that to discover if a superfluous one was provided.
            if (import_data.redeemscript) warnings.push_back("Ignoring redeemscript as this is not a P2SH script.");
            if (import_data.witnessscript) warnings.push_back("Ignoring witnessscript as this is not a (P2SH-)P2WSH script.");
            for (auto it = privkey_map.begin(); it != privkey_map.end(); ) {
                auto oldit = it++;
                if (import_data.used_keys.count(oldit->first) == 0) {
                    warnings.push_back("Ignoring irrelevant private key.");
                    privkey_map.erase(oldit);
                }
            }
            for (auto it = pubkey_map.begin(); it != pubkey_map.end(); ) {
                auto oldit = it++;
                auto key_data_it = import_data.used_keys.find(oldit->first);
                if (key_data_it == import_data.used_keys.end() || !key_data_it->second) {
                    warnings.push_back("Ignoring public key \"" + HexStr(oldit->first) + "\" as it doesn't appear inside P2PKH or P2WPKH.");
                    pubkey_map.erase(oldit);
                }
            }
        }
    }

    return warnings;
}

static UniValue ProcessImportDescriptor(ImportData& import_data, std::map<CKeyID, CPubKey>& pubkey_map, std::map<CKeyID, CKey>& privkey_map, std::set<CScript>& script_pub_keys, bool& have_solving_data, const UniValue& data, std::vector<std::pair<CKeyID, bool>>& ordered_pubkeys)
{
    UniValue warnings(UniValue::VARR);

    const std::string& descriptor = data["desc"].get_str();
    DescriptorParseOptions parse_opts;
    if (data.exists("allow_op_success")) {
        parse_opts.allow_p2tr_op_success = data["allow_op_success"].get_bool();
    }
    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs = Parse(descriptor, keys, error, /* require_checksum = */ true, parse_opts);
    if (parsed_descs.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    if (parsed_descs.at(0)->GetOutputType() == OutputType::BECH32M) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bech32m descriptors cannot be imported into legacy wallets");
    }

    std::optional<bool> internal;
    if (data.exists("internal")) {
        if (parsed_descs.size() > 1) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot have multipath descriptor while also specifying \'internal\'");
        }
        internal = data["internal"].get_bool();
    }

    have_solving_data = parsed_descs.at(0)->IsSolvable();
    const bool watch_only = data.exists("watchonly") ? data["watchonly"].get_bool() : false;

    int64_t range_start = 0, range_end = 0;
    if (!parsed_descs.at(0)->IsRange() && data.exists("range")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
    } else if (parsed_descs.at(0)->IsRange()) {
        if (!data.exists("range")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor is ranged, please specify the range");
        }
        std::tie(range_start, range_end) = ParseDescriptorRange(data["range"]);
    }

    const UniValue& priv_keys = data.exists("keys") ? data["keys"].get_array() : UniValue();

    for (size_t j = 0; j < parsed_descs.size(); ++j) {
        const auto& parsed_desc = parsed_descs.at(j);
        bool desc_internal = internal.has_value() && internal.value();
        if (parsed_descs.size() == 2) {
            desc_internal = j == 1;
        } else if (parsed_descs.size() > 2) {
            CHECK_NONFATAL(!desc_internal);
        }
        // Expand all descriptors to get public keys and scripts, and private keys if available.
        for (int i = range_start; i <= range_end; ++i) {
            FlatSigningProvider out_keys;
            std::vector<CScript> scripts_temp;
            parsed_desc->Expand(i, keys, scripts_temp, out_keys);
            std::copy(scripts_temp.begin(), scripts_temp.end(), std::inserter(script_pub_keys, script_pub_keys.end()));
            for (const auto& key_pair : out_keys.pubkeys) {
                ordered_pubkeys.emplace_back(key_pair.first, desc_internal);
            }

            for (const auto& x : out_keys.scripts) {
                import_data.import_scripts.emplace(x.second);
            }

            parsed_desc->ExpandPrivate(i, keys, out_keys);

            std::copy(out_keys.pubkeys.begin(), out_keys.pubkeys.end(), std::inserter(pubkey_map, pubkey_map.end()));
            std::copy(out_keys.keys.begin(), out_keys.keys.end(), std::inserter(privkey_map, privkey_map.end()));
            import_data.key_origins.insert(out_keys.origins.begin(), out_keys.origins.end());
        }
    }

    for (size_t i = 0; i < priv_keys.size(); ++i) {
        const auto& str = priv_keys[i].get_str();
        CKey key = DecodeSecret(str);
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");
        }
        CPubKey pubkey = key.GetPubKey();
        CKeyID id = pubkey.GetID();

        // Check if this private key corresponds to a public key from the descriptor
        if (!pubkey_map.count(id)) {
            warnings.push_back("Ignoring irrelevant private key.");
        } else {
            privkey_map.emplace(id, key);
        }
    }

    // Check if all the public keys have corresponding private keys in the import for spendability.
    // This does not take into account threshold multisigs which could be spendable without all keys.
    // Thus, threshold multisigs without all keys will be considered not spendable here, even if they are,
    // perhaps triggering a false warning message. This is consistent with the current wallet IsMine check.
    bool spendable = std::all_of(pubkey_map.begin(), pubkey_map.end(),
        [&](const std::pair<CKeyID, CPubKey>& used_key) {
            return privkey_map.count(used_key.first) > 0;
        }) && std::all_of(import_data.key_origins.begin(), import_data.key_origins.end(),
        [&](const std::pair<CKeyID, std::pair<CPubKey, KeyOriginInfo>>& entry) {
            return privkey_map.count(entry.first) > 0;
        });
    if (!watch_only && !spendable) {
        warnings.push_back("Some private keys are missing, outputs will be considered watchonly. If this is intentional, specify the watchonly flag.");
    }
    if (watch_only && spendable) {
        warnings.push_back("All private keys are provided, outputs will be considered spendable. If this is intentional, do not specify the watchonly flag.");
    }

    return warnings;
}

static UniValue ProcessImport(CWallet& wallet, const UniValue& data, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue warnings(UniValue::VARR);
    UniValue result(UniValue::VOBJ);

    try {
        const bool internal = data.exists("internal") ? data["internal"].get_bool() : false;
        // Internal addresses should not have a label
        if (internal && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal addresses should not have a label");
        }
        const std::string label{LabelFromValue(data["label"])};
        const bool add_keypool = data.exists("keypool") ? data["keypool"].get_bool() : false;

        // Add to keypool only works with privkeys disabled
        if (add_keypool && !wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Keys can only be imported to the keypool when private keys are disabled");
        }

        ImportData import_data;
        std::map<CKeyID, CPubKey> pubkey_map;
        std::map<CKeyID, CKey> privkey_map;
        std::set<CScript> script_pub_keys;
        std::vector<std::pair<CKeyID, bool>> ordered_pubkeys;
        bool have_solving_data;

        if (data.exists("scriptPubKey") && data.exists("desc")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Both a descriptor and a scriptPubKey should not be provided.");
        } else if (data.exists("scriptPubKey")) {
            warnings = ProcessImportLegacy(import_data, pubkey_map, privkey_map, script_pub_keys, have_solving_data, data, ordered_pubkeys);
        } else if (data.exists("desc")) {
            warnings = ProcessImportDescriptor(import_data, pubkey_map, privkey_map, script_pub_keys, have_solving_data, data, ordered_pubkeys);
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Either a descriptor or scriptPubKey must be provided.");
        }

        // If private keys are disabled, abort if private keys are being imported
        if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !privkey_map.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
        }

        // Check whether we have any work to do
        for (const CScript& script : script_pub_keys) {
            if (wallet.IsMine(script) & ISMINE_SPENDABLE) {
                throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script (\"" + HexStr(script) + "\")");
            }
        }

        // All good, time to import
        wallet.MarkDirty();
        if (!wallet.ImportScripts(import_data.import_scripts, timestamp)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding script to wallet");
        }
        if (!wallet.ImportPrivKeys(privkey_map, timestamp)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
        }
        if (!wallet.ImportPubKeys(ordered_pubkeys, pubkey_map, import_data.key_origins, add_keypool, timestamp)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
        }
        if (!wallet.ImportScriptPubKeys(label, script_pub_keys, have_solving_data, !internal, timestamp)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
        }

        result.pushKV("success", UniValue(true));
    } catch (const UniValue& e) {
        result.pushKV("success", UniValue(false));
        result.pushKV("error", e);
    } catch (...) {
        result.pushKV("success", UniValue(false));

        result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, "Missing required fields"));
    }
    PushWarnings(warnings, result);
    return result;
}

static int64_t GetImportTimestamp(const UniValue& data, int64_t now)
{
    if (data.exists("timestamp")) {
        const UniValue& timestamp = data["timestamp"];
        if (timestamp.isNum()) {
            return timestamp.getInt<int64_t>();
        } else if (timestamp.isStr() && timestamp.get_str() == "now") {
            return now;
        }
        throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected number or \"now\" timestamp value for key. got type %s", uvTypeName(timestamp.type())));
    }
    throw JSONRPCError(RPC_TYPE_ERROR, "Missing required timestamp field for key");
}

RPCHelpMan importmulti()
{
    return RPCHelpMan{"importmulti",
                "\nImport addresses/scripts (with private or public keys, redeem script (P2SH)), optionally rescanning the blockchain from the earliest creation time of the imported scripts. Requires a new wallet backup.\n"
                "If an address/script is imported without all of the private keys required to spend from that address, it will be watchonly. The 'watchonly' option must be set to true in this case or a warning will be returned.\n"
                "Conversely, if all the private keys are provided and the address/script is spendable, the watchonly option must be set to false, or a warning will be returned.\n"
            "\nNote: This call can take over an hour to complete if rescan is true, during that time, other rpc calls\n"
            "may report that the imported keys, addresses or scripts exist but related transactions are still missing.\n"
            "The rescan parameter can be set to false if the key was never used to create transactions. If it is set to false,\n"
            "but the key was used to create transactions, rescanblockchain needs to be called with the appropriate block range.\n"
            "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
            "Note: This command is only compatible with legacy wallets. Use \"importdescriptors\" for descriptor wallets.\n",
                {
                    {"requests", RPCArg::Type::ARR, RPCArg::Optional::NO, "Data to be imported",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"desc", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Descriptor to import. If using descriptor, do not also provide address/scriptPubKey, scripts, or pubkeys"},
                                    {"scriptPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Type of scriptPubKey (string for script, json for address). Should not be provided if using a descriptor",
                                        RPCArgOptions{.type_str={"\"<script>\" | { \"address\":\"<address>\" }", "string / json"}}
                                    },
                                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Creation time of the key expressed in " + UNIX_EPOCH_TIME + ",\n"
                                        "or the string \"now\" to substitute the current synced blockchain time. The timestamp of the oldest\n"
                                        "key will determine how far back blockchain rescans need to begin for missing wallet transactions.\n"
                                        "\"now\" can be specified to bypass scanning, for keys which are known to never have been used, and\n"
                                        "0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest key\n"
                                        "creation time of all keys being imported by the importmulti call will be scanned.",
                                        RPCArgOptions{.type_str={"timestamp | \"now\"", "integer / string"}}
                                    },
                                    {"redeemscript", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Allowed only if the scriptPubKey is a P2SH or P2SH-P2WSH address/scriptPubKey"},
                                    {"witnessscript", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Allowed only if the scriptPubKey is a P2SH-P2WSH or P2WSH address/scriptPubKey"},
                                    {"pubkeys", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Array of strings giving pubkeys to import. They must occur in P2PKH or P2WPKH scripts. They are not required when the private key is also provided (see the \"keys\" argument).",
                                        {
                                            {"pubKey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""},
                                        }
                                    },
                                    {"keys", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Array of strings giving private keys to import. The corresponding public keys must occur in the output or redeemscript.",
                                        {
                                            {"key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""},
                                        }
                                    },
                                    {"allow_op_success", RPCArg::Type::BOOL, RPCArg::Default{false}, "Allow P2MR-only OP_SUCCESS opcodes (0xbb-0xc2) inside tr() leaves. Unsafe; use for intentional testing only."},
                                    {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED, "If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import"},
                                    {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Stating whether matching outputs should be treated as not incoming payments (also known as change)"},
                                    {"watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "Stating whether matching outputs should be considered watchonly."},
                                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label to assign to the address, only allowed with internal=false"},
                                    {"keypool", RPCArg::Type::BOOL, RPCArg::Default{false}, "Stating whether imported public keys should be added to the keypool for when users request new addresses. Only allowed when wallet private keys are disabled"},
                                },
                            },
                        },
                        RPCArgOptions{.oneline_description="requests"}},
                    {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                        {
                            {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true}, "Scan the chain and mempool for wallet transactions after all imports."},
                        },
                        RPCArgOptions{.oneline_description="options"}},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "Response is an array with the same size as the input that has the execution result",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "success", ""},
                            {RPCResult::Type::ARR, "warnings", /*optional=*/true, "",
                            {
                                {RPCResult::Type::STR, "", ""},
                            }},
                            {RPCResult::Type::OBJ, "error", /*optional=*/true, "",
                            {
                                {RPCResult::Type::ELISION, "", "JSONRPC error"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("importmulti", "'[{ \"scriptPubKey\": { \"address\": \"<my address>\" }, \"timestamp\":1455191478 }, "
                                          "{ \"scriptPubKey\": { \"address\": \"<my 2nd address>\" }, \"label\": \"example 2\", \"timestamp\": 1455191480 }]'") +
                    HelpExampleCli("importmulti", "'[{ \"scriptPubKey\": { \"address\": \"<my address>\" }, \"timestamp\":1455191478 }]' '{ \"rescan\": false}'")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& mainRequest) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(mainRequest);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    EnsureLegacyScriptPubKeyMan(*pwallet, true);

    const UniValue& requests = mainRequest.params[0];

    //Default options
    bool fRescan = true;

    if (!mainRequest.params[1].isNull()) {
        const UniValue& options = mainRequest.params[1];

        if (options.exists("rescan")) {
            fRescan = options["rescan"].get_bool();
        }
    }

    WalletRescanReserver reserver(*pwallet);
    if (fRescan && !reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int64_t now = 0;
    bool fRunScan = false;
    int64_t nLowestTimestamp = 0;
    UniValue response(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);

        // Check all requests are watchonly
        bool is_watchonly{true};
        for (size_t i = 0; i < requests.size(); ++i) {
            const UniValue& request = requests[i];
            if (!request.exists("watchonly") || !request["watchonly"].get_bool()) {
                is_watchonly = false;
                break;
            }
        }
        // Wallet does not need to be unlocked if all requests are watchonly
        if (!is_watchonly) EnsureWalletIsUnlocked(wallet);

        // Verify all timestamps are present before importing any keys.
        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(nLowestTimestamp).mtpTime(now)));
        for (const UniValue& data : requests.getValues()) {
            GetImportTimestamp(data, now);
        }

        const int64_t minimumTimestamp = 1;

        for (const UniValue& data : requests.getValues()) {
            const int64_t timestamp = std::max(GetImportTimestamp(data, now), minimumTimestamp);
            const UniValue result = ProcessImport(*pwallet, data, timestamp);
            response.push_back(result);

            if (!fRescan) {
                continue;
            }

            // If at least one request was successful then allow rescan.
            if (result["success"].get_bool()) {
                fRunScan = true;
            }

            // Get the lowest timestamp.
            if (timestamp < nLowestTimestamp) {
                nLowestTimestamp = timestamp;
            }
        }
    }
    if (fRescan && fRunScan && requests.size()) {
        int64_t scannedTime = pwallet->RescanFromTime(nLowestTimestamp, reserver, /*update=*/true);
        pwallet->ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }
        if (scannedTime > nLowestTimestamp) {
            std::vector<UniValue> results = response.getValues();
            response.clear();
            response.setArray();
            size_t i = 0;
            for (const UniValue& request : requests.getValues()) {
                // If key creation date is within the successfully scanned
                // range, or if the import result already has an error set, let
                // the result stand unmodified. Otherwise replace the result
                // with an error message.
                if (scannedTime <= GetImportTimestamp(request, now) || results.at(i).exists("error")) {
                    response.push_back(results.at(i));
                } else {
                    UniValue result = UniValue(UniValue::VOBJ);
                    result.pushKV("success", UniValue(false));
                    result.pushKV(
                        "error",
                        JSONRPCError(
                            RPC_MISC_ERROR,
                            strprintf("Rescan failed for key with creation timestamp %d. There was an error reading a "
                                      "block from time %d, which is after or within %d seconds of key creation, and "
                                      "could contain transactions pertaining to the key. As a result, transactions "
                                      "and coins using this key may not appear in the wallet. This error could be "
                                      "caused by pruning or data corruption (see btxd log for details) and could "
                                      "be dealt with by downloading and rescanning the relevant blocks (see -reindex "
                                      "option and rescanblockchain RPC).",
                                GetImportTimestamp(request, now), scannedTime - TIMESTAMP_WINDOW - 1, TIMESTAMP_WINDOW)));
                    response.push_back(std::move(result));
                }
                ++i;
            }
        }
    }

    return response;
},
    };
}

UniValue ProcessDescriptorImport(CWallet& wallet, const UniValue& data, const int64_t timestamp, const std::vector<CExtKey>& master_keys) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue warnings(UniValue::VARR);
    UniValue result(UniValue::VOBJ);

    try {
        if (!data.exists("desc")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor not found.");
        }

        const std::string& descriptor = data["desc"].get_str();
        DescriptorParseOptions parse_opts;
        if (data.exists("allow_op_success")) {
            parse_opts.allow_p2tr_op_success = data["allow_op_success"].get_bool();
        }
        const bool active = data.exists("active") ? data["active"].get_bool() : false;
        const std::string label{LabelFromValue(data["label"])};

        // Parse descriptor string
        FlatSigningProvider keys;
        for (const auto& mk : master_keys) {
            keys.AddMasterKey(mk);
        }

        std::string error;
        auto parsed_descs = Parse(descriptor, keys, error, /* require_checksum = */ true, parse_opts);
        if (parsed_descs.empty()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
        }
        std::optional<bool> internal;
        if (data.exists("internal")) {
            if (parsed_descs.size() > 1) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot have multipath descriptor while also specifying \'internal\'");
            }
            internal = data["internal"].get_bool();
        }

        // Range check
        std::optional<bool> is_ranged;
        int64_t range_start = 0, range_end = 1, next_index = 0;
        if (!parsed_descs.at(0)->IsRange() && data.exists("range")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
        } else if (parsed_descs.at(0)->IsRange()) {
            if (data.exists("range")) {
                auto range = ParseDescriptorRange(data["range"]);
                range_start = range.first;
                range_end = range.second + 1; // Specified range end is inclusive, but we need range end as exclusive
            } else {
                warnings.push_back("Range not given, using default keypool range");
                range_start = 0;
                range_end = wallet.m_keypool_size;
            }
            next_index = range_start;
            is_ranged = true;

            if (data.exists("next_index")) {
                next_index = data["next_index"].getInt<int64_t>();
                // bound checks
                if (next_index < range_start || next_index >= range_end) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "next_index is out of range");
                }
            }
        }

        // Active descriptors must be ranged
        if (active && !parsed_descs.at(0)->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Active descriptors must be ranged");
        }

        // Multipath descriptors should not have a label
        if (parsed_descs.size() > 1 && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptors should not have a label");
        }

        // Ranged descriptors should not have a label
        if (is_ranged.has_value() && is_ranged.value() && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptors should not have a label");
        }

        bool desc_internal = internal.has_value() && internal.value();
        // Internal addresses should not have a label either
        if (desc_internal && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal addresses should not have a label");
        }

        // Combo descriptor check
        if (active && !parsed_descs.at(0)->IsSingleType()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Combo descriptors cannot be set to active");
        }

        // If the wallet disabled private keys, abort if private keys exist
        if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !keys.keys.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
        }

        for (size_t j = 0; j < parsed_descs.size(); ++j) {
            auto parsed_desc = std::move(parsed_descs[j]);
            if (parsed_descs.size() == 2) {
                desc_internal = j == 1;
            } else if (parsed_descs.size() > 2) {
                CHECK_NONFATAL(!desc_internal);
            }
            // Need to ExpandPrivate to check if private keys are available for all pubkeys
            FlatSigningProvider expand_keys;
            std::vector<CScript> scripts;
            if (!parsed_desc->Expand(0, keys, scripts, expand_keys)) {
                const auto output_type = parsed_desc->GetOutputType();
                if (output_type && *output_type == OutputType::P2MR) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Cannot expand P2MR descriptor without corresponding private keys. "
                        "Ranged mr() descriptors require private keys to derive PQ public keys; "
                        "xpub-only/watch-only imports are unsupported.");
                }
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot expand descriptor. Probably because of hardened derivations without private keys provided");
            }
            parsed_desc->ExpandPrivate(0, keys, expand_keys);

            // Check if all private keys are provided
            bool have_all_privkeys = !expand_keys.keys.empty();
            for (const auto& entry : expand_keys.origins) {
                const CKeyID& key_id = entry.first;
                CKey key;
                if (!expand_keys.GetKey(key_id, key)) {
                    have_all_privkeys = false;
                    break;
                }
            }

            // If private keys are enabled, check some things.
            if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
               if (!have_all_privkeys) {
                   warnings.push_back("Not all private keys provided. Some wallet functionality may return unexpected errors");
               }
            }

            WalletDescriptor w_desc(std::move(parsed_desc), timestamp, range_start, range_end, next_index);

            // Check if the wallet already contains the descriptor
            auto existing_spk_manager = wallet.GetDescriptorScriptPubKeyMan(w_desc);
            if (existing_spk_manager) {
                if (!existing_spk_manager->CanUpdateToWalletDescriptor(w_desc, error)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, error);
                }
            }

            // Add descriptor to the wallet
            auto spk_manager = wallet.AddWalletDescriptor(w_desc, keys, label, desc_internal);
            if (spk_manager == nullptr) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Could not add descriptor '%s'", descriptor));
            }

            // Set descriptor as active if necessary
            if (active) {
                if (!w_desc.descriptor->GetOutputType()) {
                    warnings.push_back("Unknown output type, cannot set descriptor to active.");
                } else {
                    wallet.AddActiveScriptPubKeyMan(spk_manager->GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            } else {
                if (w_desc.descriptor->GetOutputType()) {
                    wallet.DeactivateScriptPubKeyMan(spk_manager->GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            }
        }

        result.pushKV("success", UniValue(true));
    } catch (const UniValue& e) {
        result.pushKV("success", UniValue(false));
        result.pushKV("error", e);
    }
    PushWarnings(warnings, result);
    return result;
}

RPCHelpMan importdescriptors()
{
    return RPCHelpMan{"importdescriptors",
                "\nImport descriptors. This will trigger a rescan of the blockchain based on the earliest timestamp of all descriptors being imported. Requires a new wallet backup.\n"
            "When importing descriptors with multipath key expressions, if the multipath specifier contains exactly two elements, the descriptor produced from the second elements will be imported as an internal descriptor.\n"
            "\nNote: This call can take over an hour to complete if using an early timestamp; during that time, other rpc calls\n"
            "may report that the imported keys, addresses or scripts exist but related transactions are still missing.\n"
            "The rescan is significantly faster if block filters are available (using startup option \"-blockfilterindex=1\").\n",
                {
                    {"requests", RPCArg::Type::ARR, RPCArg::Optional::NO, "Data to be imported",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "Descriptor to import."},
                                    {"allow_op_success", RPCArg::Type::BOOL, RPCArg::Default{false}, "Allow P2MR-only OP_SUCCESS opcodes (0xbb-0xc2) inside tr() leaves. Unsafe; use for intentional testing only."},
                                    {"active", RPCArg::Type::BOOL, RPCArg::Default{false}, "Set this descriptor to be the active descriptor for the corresponding output type/externality"},
                                    {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED, "If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import"},
                                    {"next_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If a ranged descriptor is set to active, this specifies the next index to generate addresses from"},
                                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time from which to start rescanning the blockchain for this descriptor, in " + UNIX_EPOCH_TIME + "\n"
                                        "Use the string \"now\" to substitute the current synced blockchain time.\n"
                                        "\"now\" can be specified to bypass scanning, for outputs which are known to never have been used, and\n"
                                        "0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp\n"
                                        "of all descriptors being imported will be scanned as well as the mempool.",
                                        RPCArgOptions{.type_str={"timestamp | \"now\"", "integer / string"}}
                                    },
                                    {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether matching outputs should be treated as not incoming payments (e.g. change)"},
                                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label to assign to the address, only allowed with internal=false. Disabled for ranged descriptors"},
                                },
                            },
                        },
                        RPCArgOptions{.oneline_description="requests"}},
                    {"seeds", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "BIP32 master seeds for the above descriptors",
                        {
                            {"shares", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "a codex32 (BIP 93) encoded seed, or list of codex32-encoded shares",
                                {
                                    {"share 1", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""},
                                },
                            },
                        },
                        RPCArgOptions{.oneline_description="seeds"}},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "Response is an array with the same size as the input that has the execution result",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "success", ""},
                            {RPCResult::Type::ARR, "warnings", /*optional=*/true, "",
                            {
                                {RPCResult::Type::STR, "", ""},
                            }},
                            {RPCResult::Type::OBJ, "error", /*optional=*/true, "",
                            {
                                {RPCResult::Type::ELISION, "", "JSONRPC error"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"internal\": true }, "
                                          "{ \"desc\": \"<my descriptor 2>\", \"label\": \"example 2\", \"timestamp\": 1455191480 }]'") +
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"active\": true, \"range\": [0,100], \"label\": \"<my bech32 wallet>\" }]'")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& main_request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(main_request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    //  Make sure wallet is a descriptor wallet
    if (!pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "importdescriptors is not available for non-descriptor wallets");
    }

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    // Ensure that the wallet is not locked for the remainder of this RPC, as
    // the passphrase is used to top up the keypool.
    LOCK(pwallet->m_relock_mutex);

    const UniValue& requests = main_request.params[0];
    const int64_t minimum_timestamp = 1;
    int64_t now = 0;
    int64_t lowest_timestamp = 0;
    bool rescan = false;

    // Parse codex32 strings
    std::vector<CExtKey> master_keys;
    if (main_request.params[1].isArray()) {
        const auto& req_seeds = main_request.params[1].get_array();
        master_keys.reserve(req_seeds.size());
        for (size_t i = 0; i < req_seeds.size(); ++i) {
            const auto& req_shares = req_seeds[i].get_array();
            std::vector<codex32::Result> shares;
            shares.reserve(req_shares.size());
            for (size_t j = 0; j < req_shares.size(); ++j) {
                if (!req_shares[j].isStr()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "codex32 shares must be strings");
                }
                codex32::Result key_res{req_shares[j].get_str()};
                if (!key_res.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid codex32 share: " + codex32::ErrorString(key_res.error()));
                }
                shares.push_back(key_res);
            }

            // Recover seed
            std::vector<unsigned char> seed;
            if (shares.size() == 1) {
                if (shares[0].GetShareIndex() != 's') {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid codex32: single share must be the S share");
                }
                seed = shares[0].GetPayload();
            } else {
                codex32::Result s{shares, 's'};
                if (!s.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Failed to derive codex32 seed: " + codex32::ErrorString(s.error()));
                }
                seed = s.GetPayload();
            }

            CExtKey master_key;
            master_key.SetSeed(Span{(std::byte*) seed.data(), seed.size()});
            master_keys.push_back(master_key);
        }
    }

    UniValue response(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);

        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(lowest_timestamp).mtpTime(now)));

        // Get all timestamps and extract the lowest timestamp
        for (const UniValue& request : requests.getValues()) {
            // This throws an error if "timestamp" doesn't exist
            const int64_t timestamp = std::max(GetImportTimestamp(request, now), minimum_timestamp);
            const UniValue result = ProcessDescriptorImport(*pwallet, request, timestamp, master_keys);
            response.push_back(result);

            if (lowest_timestamp > timestamp ) {
                lowest_timestamp = timestamp;
            }

            // If we know the chain tip, and at least one request was successful then allow rescan
            if (!rescan && result["success"].get_bool()) {
                rescan = true;
            }
        }
        pwallet->ConnectScriptPubKeyManNotifiers();
    }

    // Rescan the blockchain using the lowest timestamp
    if (rescan) {
        int64_t scanned_time = pwallet->RescanFromTime(lowest_timestamp, reserver, /*update=*/true);
        pwallet->ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }

        if (scanned_time > lowest_timestamp) {
            std::vector<UniValue> results = response.getValues();
            response.clear();
            response.setArray();

            // Compose the response
            for (unsigned int i = 0; i < requests.size(); ++i) {
                const UniValue& request = requests.getValues().at(i);

                // If the descriptor timestamp is within the successfully scanned
                // range, or if the import result already has an error set, let
                // the result stand unmodified. Otherwise replace the result
                // with an error message.
                if (scanned_time <= GetImportTimestamp(request, now) || results.at(i).exists("error")) {
                    response.push_back(results.at(i));
                } else {
                    std::string error_msg{strprintf("Rescan failed for descriptor with timestamp %d. There "
                            "was an error reading a block from time %d, which is after or within %d seconds "
                            "of key creation, and could contain transactions pertaining to the desc. As a "
                            "result, transactions and coins using this desc may not appear in the wallet.",
                            GetImportTimestamp(request, now), scanned_time - TIMESTAMP_WINDOW - 1, TIMESTAMP_WINDOW)};
                    if (pwallet->chain().havePruned()) {
                        error_msg += strprintf(" This error could be caused by pruning or data corruption "
                                "(see btxd log for details) and could be dealt with by downloading and "
                                "rescanning the relevant blocks (see -reindex option and rescanblockchain RPC).");
                    } else if (pwallet->chain().hasAssumedValidChain()) {
                        error_msg += strprintf(" This error is likely caused by an in-progress assumeutxo "
                                "background sync. Check logs or getchainstates RPC for assumeutxo background "
                                "sync progress and try again later.");
                    } else {
                        error_msg += strprintf(" This error could potentially caused by data corruption. If "
                                "the issue persists you may want to reindex (see -reindex option).");
                    }

                    UniValue result = UniValue(UniValue::VOBJ);
                    result.pushKV("success", UniValue(false));
                    result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, error_msg));
                    response.push_back(std::move(result));
                }
            }
        }
    }

    return response;
},
    };
}

RPCHelpMan listdescriptors()
{
    return RPCHelpMan{
        "listdescriptors",
        "\nList all descriptors present in a descriptor-enabled wallet.\n",
        {
            {"private", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show private descriptors."}
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
            {RPCResult::Type::ARR, "descriptors", "Array of descriptor objects (sorted by descriptor string representation)",
            {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "desc", "Descriptor string representation"},
                    {RPCResult::Type::NUM, "timestamp", "The creation time of the descriptor"},
                    {RPCResult::Type::BOOL, "active", "Whether this descriptor is currently used to generate new addresses"},
                    {RPCResult::Type::BOOL, "internal", /*optional=*/true, "True if this descriptor is used to generate change addresses. False if this descriptor is used to generate receiving addresses; defined only for active descriptors"},
                    {RPCResult::Type::ARR_FIXED, "range", /*optional=*/true, "Defined only for ranged descriptors", {
                        {RPCResult::Type::NUM, "", "Range start inclusive"},
                        {RPCResult::Type::NUM, "", "Range end inclusive"},
                    }},
                    {RPCResult::Type::NUM, "next", /*optional=*/true, "Same as next_index field. Kept for compatibility reason."},
                    {RPCResult::Type::NUM, "next_index", /*optional=*/true, "The next index to generate addresses from; defined only for ranged descriptors"},
                }},
            }}
        }},
        RPCExamples{
            HelpExampleCli("listdescriptors", "") + HelpExampleRpc("listdescriptors", "")
            + HelpExampleCli("listdescriptors", "true") + HelpExampleRpc("listdescriptors", "true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    const bool priv = !request.params[0].isNull() && request.params[0].get_bool();
    return BuildListDescriptorsResult(*wallet, priv);
},
    };
}

RPCHelpMan backupwallet()
{
    return RPCHelpMan{"backupwallet",
                "\nSafely copies the current wallet file to the specified destination, which can either be a directory or a path with a filename.\n",
                {
                    {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination directory or file"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan backupwalletbundle()
{
    return RPCHelpMan{"backupwalletbundle",
                "\nCreate a wallet backup bundle directory containing backupwallet output, descriptor exports,\n"
                "shielded viewing-key exports when permitted, transparent + shielded balance snapshots,\n"
                "integrity metadata, and a manifest.\n"
                "After the post-61000 privacy fork, raw shielded viewing-key exports are disabled and omitted\n"
                "include_viewing_keys defaults to false.\n"
                "\nIf the wallet is encrypted and locked, provide the passphrase as the second argument or use\n"
                "btx-cli -stdinwalletpassphrase so the CLI prompts without echoing the passphrase.\n",
                {
                    {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "A new directory path that will receive the bundle files."},
                    {"wallet_passphrase", RPCArg::Type::STR, RPCArg::DefaultHint{"omit if wallet is already unlocked"}, "Wallet passphrase used for temporary private exports."},
                    {"include_viewing_keys", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true before post-61000, false after"}, "Export shielded viewing keys into shielded_viewing_keys/. Omitted defaults follow the active privacy regime."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "wallet_name", "Wallet name"},
                        {RPCResult::Type::STR, "bundle_dir", "Bundle directory path"},
                        {RPCResult::Type::STR, "backup_file", "Primary backupwallet output inside the bundle"},
                        {RPCResult::Type::BOOL, "unlocked_by_rpc", "True if the RPC temporarily unlocked and relocked the wallet"},
                        {RPCResult::Type::ARR, "files", "Files written by the bundle export",
                            {{RPCResult::Type::STR, "", "Absolute file path"}}},
                        {RPCResult::Type::ARR, "warnings", "Non-fatal warnings generated while exporting",
                            {{RPCResult::Type::STR, "", "Warning message"}}},
                        {RPCResult::Type::OBJ, "integrity", "Wallet integrity snapshot captured during export", WalletIntegrityDoc()},
                    }},
                RPCExamples{
                    HelpExampleCli("backupwalletbundle", "\"/var/backups/mywallet-bundle\"") +
                    HelpExampleCli("backupwalletbundle", "\"/var/backups/mywallet-bundle\" \"my pass phrase\"") +
                    HelpExampleRpc("backupwalletbundle", "\"/var/backups/mywallet-bundle\", \"my pass phrase\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    const std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    const fs::path bundle_dir = fs::u8path(request.params[0].get_str());
    const std::optional<std::string> wallet_passphrase = request.params[1].isNull()
        ? std::nullopt
        : std::optional<std::string>(request.params[1].get_str());
    const bool include_viewing_keys = request.params[2].isNull()
        ? DefaultIncludeViewingKeysInWalletBundle(*wallet)
        : request.params[2].get_bool();
    const WalletBundleExportArtifacts artifacts = ExportWalletBundleToDirectory(*wallet, bundle_dir, wallet_passphrase,
                                                                                include_viewing_keys, "backupwalletbundle");

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallet_name", wallet->GetName());
    result.pushKV("bundle_dir", fs::PathToString(fs::absolute(bundle_dir)));
    result.pushKV("backup_file", fs::PathToString(fs::absolute(artifacts.backup_path)));
    result.pushKV("unlocked_by_rpc", artifacts.unlocked_by_rpc);
    UniValue out_files(UniValue::VARR);
    for (const auto& file : artifacts.files_written) out_files.push_back(file);
    result.pushKV("files", std::move(out_files));
    UniValue out_warnings(UniValue::VARR);
    for (const auto& warning : artifacts.warnings) out_warnings.push_back(warning);
    result.pushKV("warnings", std::move(out_warnings));
    result.pushKV("integrity", artifacts.integrity);
    return result;
},
    };
}

RPCHelpMan backupwalletbundlearchive()
{
    return RPCHelpMan{"backupwalletbundlearchive",
                "\nCreate an encrypted single-file wallet backup archive containing the same files exported by\n"
                "backupwalletbundle. The archive is encrypted with a dedicated archive passphrase so it can be\n"
                "stored or transferred as one sealed file.\n"
                "After the post-61000 privacy fork, raw shielded viewing-key exports are disabled and omitted\n"
                "include_viewing_keys defaults to false.\n"
                "\nIf the wallet is encrypted and locked, provide the wallet passphrase as the third argument or use\n"
                "btx-cli -stdinwalletpassphrase. Use btx-cli -stdinbundlepassphrase to enter the archive passphrase\n"
                "without echoing it.\n",
                {
                    {"destination_archive", RPCArg::Type::STR, RPCArg::Optional::NO, "A new file path that will receive the encrypted archive."},
                    {"archive_passphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "Passphrase used to encrypt the bundle archive."},
                    {"wallet_passphrase", RPCArg::Type::STR, RPCArg::DefaultHint{"omit if wallet is already unlocked"}, "Wallet passphrase used for temporary private exports."},
                    {"include_viewing_keys", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true before post-61000, false after"}, "Export shielded viewing keys into the archive. Omitted defaults follow the active privacy regime."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "wallet_name", "Wallet name"},
                        {RPCResult::Type::STR, "archive_file", "Archive file path"},
                        {RPCResult::Type::STR, "bundle_name", "Logical bundle directory name stored inside the archive"},
                        {RPCResult::Type::STR, "archive_sha256", "SHA256 hash of the encrypted archive file"},
                        {RPCResult::Type::BOOL, "unlocked_by_rpc", "True if the RPC temporarily unlocked and relocked the wallet"},
                        {RPCResult::Type::ARR, "bundle_files", "Relative bundle paths stored inside the archive",
                            {{RPCResult::Type::STR, "", "Relative file path"}}},
                        {RPCResult::Type::ARR, "warnings", "Non-fatal warnings generated while exporting",
                            {{RPCResult::Type::STR, "", "Warning message"}}},
                        {RPCResult::Type::OBJ, "integrity", "Wallet integrity snapshot captured during export", WalletIntegrityDoc()},
                    }},
                RPCExamples{
                    HelpExampleCli("backupwalletbundlearchive", "\"/var/backups/mywallet.bundle.btx\" \"archive passphrase\"") +
                    HelpExampleRpc("backupwalletbundlearchive", "\"/var/backups/mywallet.bundle.btx\", \"archive passphrase\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    const std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    const fs::path archive_path = fs::u8path(request.params[0].get_str());
    const std::string archive_passphrase = request.params[1].get_str();
    const std::optional<std::string> wallet_passphrase = request.params[2].isNull()
        ? std::nullopt
        : std::optional<std::string>(request.params[2].get_str());
    const bool include_viewing_keys = request.params[3].isNull()
        ? DefaultIncludeViewingKeysInWalletBundle(*wallet)
        : request.params[3].get_bool();

    EnsureFreshFileDestination(archive_path);
    const fs::path parent_dir = archive_path.parent_path().empty() ? fs::current_path() : archive_path.parent_path();
    const std::string bundle_name = WalletBundleDirectoryName(*wallet);
    const WalletBundleArchiveExportArtifacts artifacts = ExportWalletBundleToArchivePayload(
        *wallet,
        wallet_passphrase,
        include_viewing_keys,
        "backupwalletbundlearchive",
        bundle_name,
        parent_dir);

    const DataStream& payload_stream = artifacts.payload_stream;

    WalletBundleArchiveEnvelope envelope;
    try {
        envelope = EncryptWalletBundleArchivePayload(payload_stream, archive_passphrase);
    } catch (const std::bad_alloc&) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("Insufficient memory while encrypting the wallet bundle archive payload (%u bytes)",
                                     static_cast<uint32_t>(payload_stream.size())));
    }

    DataStream archive_stream{};
    try {
        archive_stream << envelope;
    } catch (const std::bad_alloc&) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient memory while finalizing the wallet bundle archive");
    }
    const Span<const unsigned char> archive_bytes{UCharCast(archive_stream.data()), archive_stream.size()};
    const uint256 archive_sha256 = Hash(archive_bytes);
    WriteBinaryFileAtomically(archive_path, archive_bytes);

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallet_name", wallet->GetName());
    result.pushKV("archive_file", fs::PathToString(fs::absolute(archive_path)));
    result.pushKV("bundle_name", bundle_name);
    result.pushKV("archive_sha256", archive_sha256.GetHex());
    result.pushKV("unlocked_by_rpc", artifacts.unlocked_by_rpc);
    UniValue bundle_files(UniValue::VARR);
    for (const auto& file : artifacts.bundle_files) bundle_files.push_back(file);
    result.pushKV("bundle_files", std::move(bundle_files));
    UniValue out_warnings(UniValue::VARR);
    for (const auto& warning : artifacts.warnings) out_warnings.push_back(warning);
    result.pushKV("warnings", std::move(out_warnings));
    result.pushKV("integrity", artifacts.integrity);
    return result;
},
    };
}


RPCHelpMan restorewalletbundlearchive()
{
    return RPCHelpMan{
        "restorewalletbundlearchive",
        "\nRestores and loads a wallet from an encrypted wallet bundle archive created by\n"
        "backupwalletbundlearchive.\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name that will be applied to the restored wallet"},
            {"archive_file", RPCArg::Type::STR, RPCArg::Optional::NO, "The encrypted archive file that will be used to restore the wallet."},
            {"archive_passphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "Passphrase used to decrypt the archive."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if restored successfully."},
                {RPCResult::Type::STR, "archive_file", "The archive file that was restored"},
                {RPCResult::Type::STR, "bundle_name", "Logical bundle directory name stored inside the archive"},
                {RPCResult::Type::OBJ, "bundled_manifest", "Manifest captured in the archive", WalletBundleManifestDoc()},
                {RPCResult::Type::OBJ, "bundled_integrity", "Integrity snapshot captured in the archive", WalletIntegrityDoc()},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to restoring and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("restorewalletbundlearchive", "\"testwallet\" \"home\\backups\\testwallet.bundle.btx\" \"archive passphrase\"") +
            HelpExampleRpc("restorewalletbundlearchive", "\"testwallet\", \"home\\backups\\testwallet.bundle.btx\", \"archive passphrase\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    WalletContext& context = EnsureWalletContext(request.context);
    const fs::path archive_file = fs::u8path(request.params[1].get_str());
    const std::string archive_passphrase = request.params[2].get_str();
    const std::string wallet_name = request.params[0].get_str();
    const std::optional<bool> load_on_start = request.params[3].isNull()
        ? std::nullopt
        : std::optional<bool>(request.params[3].get_bool());

    const WalletBundleArchiveEnvelope envelope = [&]() {
        const std::vector<unsigned char> archive_bytes = ReadBinaryFile(archive_file);
        DataStream archive_stream{Span<const unsigned char>{archive_bytes.data(), archive_bytes.size()}};
        WalletBundleArchiveEnvelope parsed;
        try {
            archive_stream >> parsed;
        } catch (const std::ios_base::failure&) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive could not be decoded");
        }
        if (!archive_stream.empty()) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive has trailing data");
        }
        return parsed;
    }();

    WalletBundleArchivePayload payload;
    try {
        payload = DecryptWalletBundleArchivePayload(envelope, archive_passphrase);
    } catch (const std::bad_alloc&) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient memory while decrypting the wallet bundle archive");
    }
    const std::string bundle_name = ValidateWalletBundleArchiveDirectoryName(payload.bundle_name);
    const fs::path backup_relative = fs::u8path(payload.backup_file);
    const std::vector<unsigned char>* backup_bytes = FindWalletBundleArchiveFileData(payload, backup_relative);
    if (backup_bytes == nullptr) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive is missing its backup file");
    }
    const std::vector<unsigned char>* manifest_bytes =
        FindWalletBundleArchiveFileData(payload, fs::u8path("manifest.json"));
    if (manifest_bytes == nullptr) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive is missing manifest.json");
    }
    const std::vector<unsigned char>* integrity_bytes =
        FindWalletBundleArchiveFileData(payload, fs::u8path("z_verifywalletintegrity.json"));
    if (integrity_bytes == nullptr) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wallet bundle archive is missing z_verifywalletintegrity.json");
    }
    const UniValue bundled_manifest = ReadJsonBytes(
        Span<const unsigned char>{manifest_bytes->data(), manifest_bytes->size()},
        "manifest.json");
    const UniValue bundled_integrity = ReadJsonBytes(
        Span<const unsigned char>{integrity_bytes->data(), integrity_bytes->size()},
        "z_verifywalletintegrity.json");
    ValidateWalletBundleArchiveMetadata(payload, bundled_manifest, bundled_integrity);

    const fs::path temp_root_dir = CreateUniqueTempDirectory(fs::temp_directory_path(), bundle_name + ".restore");
    ScopedCleanupDirectory cleanup(temp_root_dir);
    const fs::path backup_path = temp_root_dir / backup_relative;
    EnsureParentDirectories(backup_path);
    WriteBinaryFile(backup_path, Span<const unsigned char>{backup_bytes->data(), backup_bytes->size()});

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    const std::shared_ptr<CWallet> wallet = RestoreWallet(context, backup_path, wallet_name, load_on_start, status, error, warnings);
    HandleWalletError(wallet, status, error);
    AddLockedShieldedAccountingWarningIfNeeded(*wallet, warnings, "restore");

    UniValue result(UniValue::VOBJ);
    result.pushKV("name", wallet->GetName());
    result.pushKV("archive_file", fs::PathToString(fs::absolute(archive_file)));
    result.pushKV("bundle_name", bundle_name);
    result.pushKV("bundled_manifest", bundled_manifest);
    result.pushKV("bundled_integrity", bundled_integrity);
    PushWarnings(warnings, result);
    return result;

},
    };
}

RPCHelpMan restorewallet()
{
    return RPCHelpMan{
        "restorewallet",
        "\nRestores and loads a wallet from backup.\n"
        "\nThe rescan is significantly faster if a descriptor wallet is restored"
        "\nand block filters are available (using startup option \"-blockfilterindex=1\").\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name that will be applied to the restored wallet"},
            {"backup_file", RPCArg::Type::STR, RPCArg::Optional::NO, "The backup file that will be used to restore the wallet."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if restored successfully."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to restoring and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleRpc("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleCliNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak"}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak"}, {"load_on_startup", true}})
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureNotWalletRestricted(request);

    WalletContext& context = EnsureWalletContext(request.context);

    auto backup_file = fs::u8path(request.params[1].get_str());

    std::string wallet_name = request.params[0].get_str();

    std::optional<bool> load_on_start = request.params[2].isNull() ? std::nullopt : std::optional<bool>(request.params[2].get_bool());

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    const std::shared_ptr<CWallet> wallet = RestoreWallet(context, backup_file, wallet_name, load_on_start, status, error, warnings);

    HandleWalletError(wallet, status, error);
    AddLockedShieldedAccountingWarningIfNeeded(*wallet, warnings, "restore");

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;

},
    };
}
} // namespace wallet
