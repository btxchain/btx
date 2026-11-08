// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <key_io.h>
#include <outputtype.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <script/descriptor.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <wallet/context.h>
#include <wallet/rpc/wallet.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <csignal>
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_labels_export_tests, WalletTestingSetup)

#ifndef WIN32
BOOST_AUTO_TEST_CASE(exportlabels_refuses_a_short_write)
{
    // exportlabels buffered the records with fwrite and did not check the
    // final fclose, so a write that failed only at close (a full disk) was
    // reported as written. RLIMIT_FSIZE stands in for the full disk.
    std::array<unsigned char, 32> seed;
    seed.fill(0x3c);
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
        for (int i = 0; i < 8; ++i) {
            BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, "label number " + std::to_string(i)));
        }
    }
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    const fs::path dir{m_path_root / "labels"};
    fs::create_directories(dir);
    const auto export_to = [&](const fs::path& path) {
        UniValue params(UniValue::VARR);
        params.push_back(fs::PathToString(path));
        return CallWalletRpc(context, "exportlabels", params);
    };
    const UniValue full = export_to(dir / "full.jsonl");
    BOOST_CHECK_EQUAL(full["labels"].getInt<int>(), 8);
    BOOST_REQUIRE_GT(fs::file_size(dir / "full.jsonl"), 64U);

    const fs::path short_path{dir / "short.jsonl"};
    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = 64;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    std::optional<UniValue> result;
    try {
        result = export_to(short_path);
    } catch (const UniValue&) {
    }
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);

    BOOST_CHECK_MESSAGE(!result, "exportlabels reported success for a short write");
    BOOST_CHECK(!fs::exists(short_path));

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
