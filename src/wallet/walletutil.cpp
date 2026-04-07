// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <common/args.h>
#include <key_io.h>
#include <logging.h>

namespace wallet {
namespace {

bool UseSLHOnlyPQDescriptorDefaults()
{
    // Post-emergency default: if ML-DSA is disabled from genesis for this
    // network, create SLH-only descriptors for new addresses.
    return Params().GetConsensus().nMLDSADisableHeight == 0;
}

std::string BuildDefaultPQTree(const std::string& key_expr)
{
    if (UseSLHOnlyPQDescriptorDefaults()) {
        return "mr(pk_slh(" + key_expr + "))";
    }
    return "mr(" + key_expr + ",pk_slh(" + key_expr + "))";
}

} // namespace

fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

bool IsFeatureSupported(int wallet_version, int feature_version)
{
    return wallet_version >= feature_version;
}

WalletFeature GetClosestWalletFeature(int version)
{
    static constexpr std::array wallet_features{FEATURE_LATEST, FEATURE_PRE_SPLIT_KEYPOOL, FEATURE_NO_DEFAULT_KEY, FEATURE_HD_SPLIT, FEATURE_HD, FEATURE_COMPRPUBKEY, FEATURE_WALLETCRYPT, FEATURE_BASE};
    for (const WalletFeature& wf : wallet_features) {
        if (version >= wf) return wf;
    }
    return static_cast<WalletFeature>(0);
}

WalletDescriptor GenerateWalletDescriptor(const CExtPubKey& master_key, const OutputType& addr_type, bool internal)
{
    int64_t creation_time = GetTime();

    std::string xpub = EncodeExtPubKey(master_key);

    if (addr_type == OutputType::P2MR) {
        std::string deriv = xpub + "/87h";
        // Mainnet derives at 0', testnet and regtest derive at 1'
        deriv += Params().IsTestChain() ? "/1h" : "/0h";
        deriv += "/0h";
        deriv += internal ? "/1" : "/0";
        deriv += "/*";

        const std::string desc_str = BuildDefaultPQTree(deriv);

        FlatSigningProvider keys;
        std::string error;
        std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
        WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
        return w_desc;
    }

    // Build descriptor string
    std::string desc_prefix;
    std::string desc_suffix = "/*)";
    switch (addr_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(" + xpub + "/44h";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(" + xpub + "/49h";
        desc_suffix += ")";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(" + xpub + "/84h";
        break;
    }
    case OutputType::BECH32M: {
        desc_prefix = "tr(" + xpub + "/86h";
        break;
    }
    case OutputType::P2MR:
        assert(false);
        break;
    case OutputType::UNKNOWN: {
        // We should never have a DescriptorScriptPubKeyMan for an UNKNOWN OutputType,
        // so if we get to this point something is wrong
        assert(false);
    }
    } // no default case, so the compiler can warn about missing cases
    assert(!desc_prefix.empty());

    // Mainnet derives at 0', testnet and regtest derive at 1'
    if (Params().IsTestChain()) {
        desc_prefix += "/1h";
    } else {
        desc_prefix += "/0h";
    }

    std::string internal_path = internal ? "/1" : "/0";
    std::string desc_str = desc_prefix + "/0h" + internal_path + desc_suffix;

    // Make the descriptor
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
    WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
    return w_desc;
}

WalletDescriptor GeneratePQWalletDescriptor(Span<const unsigned char> pq_seed, bool internal)
{
    int64_t creation_time = GetTime();

    const std::string seed_hex = HexStr(pq_seed);
    const std::string coin_type = Params().IsTestChain() ? "1h" : "0h";
    const std::string change = internal ? "1" : "0";

    // pqhd(seed/coin_typeh/accounth/change/*)
    const std::string pqhd = "pqhd(" + seed_hex + "/" + coin_type + "/0h/" + change + "/*)";

    // Default wallet tree: 2-leaf with ML-DSA primary and SLH-DSA backup
    const std::string desc_str = "mr(" + pqhd + ",pk_slh(" + pqhd + "))";

    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
    if (desc.empty()) {
        throw std::runtime_error(strprintf("Failed to parse PQ wallet descriptor: %s", error));
    }
    WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
    return w_desc;
}

} // namespace wallet
