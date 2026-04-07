// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <common/args.h>
#include <tinyformat.h>
#include <util/chaintype.h>

#include <assert.h>

void SetupChainParamsBaseOptions(ArgsManager& argsman)
{
    argsman.AddArg("-chain=<chain>", "Use the chain <chain> (default: main). Allowed values: " LIST_CHAIN_NAMES, ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                 "This is intended for regression testing tools and app development. Equivalent to -chain=regtest.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-shieldedv2dev", "Use the isolated shieldedv2dev development chain. Equivalent to -chain=shieldedv2dev.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testactivationheight=name@height.", "Set the activation height of 'name' (segwit, bip34, dersig, cltv, csv). (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-testnet", "Use the testnet3 chain. Equivalent to -chain=test. Support for testnet3 is deprecated and will be removed in an upcoming release. Consider moving to testnet4 now by using -testnet4.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testnet4", "Use the testnet4 chain. Equivalent to -chain=testnet4.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-vbparams=deployment:start:end[:min_activation_height]", "Use given start/end times and min_activation_height for specified version bits deployment (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmsgstart=<hex>", "Override regtest message-start magic as 4 bytes (8 hex chars, regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestport=<port>", "Override regtest default P2P port (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestgenesisntime=<n>", "Override regtest genesis nTime field (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestgenesisnonce=<n>", "Override regtest genesis nNonce field (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestgenesisbits=<hex>", "Override regtest genesis nBits field (4 bytes, 8 hex chars, regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestgenesisversion=<n>", "Override regtest genesis nVersion field (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-mldsadisableheight=<n>", "Set ML-DSA consensus disable height for regtest (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestshieldedmatrictdisableheight=<n>", "Override regtest shielded MatRiCT disable height (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulbindingheight=<n>", "Override regtest MatMul Freivalds transcript-binding activation height (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulproductdigestheight=<n>", "Override regtest MatMul product-committed digest activation height (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulrequireproductpayload=<0|1>", "Override whether regtest MatMul blocks must carry a product payload (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulaserthalflife=<n>", "Override regtest MatMul ASERT half-life in seconds (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulaserthalflifeupgradeheight=<n>", "Override regtest MatMul ASERT half-life upgrade height (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulaserthalflifeupgrade=<n>", "Override regtest MatMul ASERT half-life upgrade value in seconds (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulprehashepsilonbitsupgradeheight=<n>", "Override regtest MatMul pre-hash epsilon upgrade height (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtestmatmulprehashepsilonbitsupgrade=<n>", "Override regtest MatMul pre-hash epsilon upgrade bits (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signet", "Use the signet chain. Equivalent to -chain=signet. Note that the network is defined by the -signetchallenge parameter", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetchallenge", "Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global default signet test network challenge)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetblocktime", "Difficulty adjustment will target a block time of the given amount in seconds (only for custom signet networks, must have -signetchallenge set; defaults to 10 minutes)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetseednode", "Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used multiple times to specify multiple seed nodes; defaults to the global default signet test network seed node(s))", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

/**
 * BTX default RPC ports.
 *
 * Mainnet/testnet use BTX-native ranges to reduce operator confusion with
 * Bitcoin defaults; testnet4/signet/regtest keep their historical defaults.
 */
std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return std::make_unique<CBaseChainParams>("", 19334);
    case ChainType::TESTNET:
        return std::make_unique<CBaseChainParams>("testnet3", 29334);
    case ChainType::TESTNET4:
        return std::make_unique<CBaseChainParams>("testnet4", 48332);
    case ChainType::SIGNET:
        return std::make_unique<CBaseChainParams>("signet", 38332);
    case ChainType::REGTEST:
        return std::make_unique<CBaseChainParams>("regtest", 18443);
    case ChainType::SHIELDEDV2DEV:
        return std::make_unique<CBaseChainParams>("shieldedv2dev", 19443);
    }
    assert(false);
}

void SelectBaseParams(const ChainType chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
    gArgs.SelectConfigNetwork(ChainTypeToString(chain));
}
