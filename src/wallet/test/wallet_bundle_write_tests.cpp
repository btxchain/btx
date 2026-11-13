// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <outputtype.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <script/descriptor.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <wallet/context.h>
#include <wallet/rpc/wallet.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <csignal>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>

#ifndef WIN32
#include <sys/resource.h>
#endif

namespace wallet {
namespace {

UniValue CallWalletRpc(WalletContext& context, const std::string& name, UniValue params)
{
    JSONRPCRequest req;
    req.context = &context;
    req.m_wallet_restriction = "";
    req.params = std::move(params);
    for (const CRPCCommand& cmd : GetWalletRPCCommands()) {
        if (cmd.name == name) {
            UniValue result;
            BOOST_REQUIRE(cmd.actor(req, result, /*last_handler=*/true));
            return result;
        }
    }
    BOOST_FAIL("wallet RPC " + name + " is not registered");
    return UniValue::VNULL;
}

std::string ReadFile(const fs::path& path)
{
    std::ifstream in{path, std::ios::binary};
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_bundle_write_tests, WalletTestingSetup)

#ifndef WIN32
BOOST_AUTO_TEST_CASE(exportwalletbundle_refuses_a_short_write)
{
    // A .btxwallet file holds the PQ master seed, and for a browser wallet it
    // is the only copy. A full disk can fail only the flush at close, so the
    // export must fail and not report a short or empty file as written.
    // RLIMIT_FSIZE stands in for the full disk: it fails every write past the
    // limit with EFBIG.
    std::array<unsigned char, 32> seed;
    seed.fill(0x5a);
    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        for (const bool internal : {false, true}) {
            WalletDescriptor w_desc = GeneratePQWalletDescriptor(seed, internal);
            BOOST_REQUIRE(w_desc.descriptor);
            auto* spkm = wallet->AddWalletDescriptor(w_desc, FlatSigningProvider{}, "", internal);
            BOOST_REQUIRE(spkm != nullptr);
            wallet->AddActiveScriptPubKeyMan(spkm->GetID(), OutputType::P2MR, internal);
        }
    }
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    const fs::path dir{m_path_root / "bundles"};
    fs::create_directories(dir);
    const auto export_params = [](const fs::path& path) {
        UniValue params(UniValue::VARR);
        params.push_back(fs::PathToString(path));
        params.push_back(UniValue{});
        params.push_back(1);
        return params;
    };

    // With room the bundle is written in full; it is far larger than the limit below.
    const fs::path full_path{dir / "full.btxwallet.json"};
    const UniValue full = CallWalletRpc(context, "exportwalletbundle", export_params(full_path));
    BOOST_CHECK(full["success"].get_bool());
    const std::string bundle{ReadFile(full_path)};
    UniValue parsed;
    BOOST_REQUIRE(parsed.read(bundle));
    BOOST_CHECK_EQUAL(parsed["pq_master_seed"].get_str(), HexStr(seed));
    BOOST_REQUIRE_GT(bundle.size(), 64U);

    const fs::path short_path{dir / "short.btxwallet.json"};
    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = 64;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    std::optional<UniValue> result;
    std::string error;
    try {
        result = CallWalletRpc(context, "exportwalletbundle", export_params(short_path));
    } catch (const UniValue& e) {
        error = e["message"].get_str();
    }
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);

    if (result) {
        // The export claimed success: then the file must be the whole bundle.
        BOOST_CHECK_EQUAL(ReadFile(short_path).size(), bundle.size());
    }
    BOOST_CHECK_MESSAGE(!result, "exportwalletbundle reported success for a short write");
    BOOST_CHECK(error.find("Failed to write") != std::string::npos);
    BOOST_CHECK(!fs::exists(short_path));

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
