// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <string>

#ifndef WIN32
#include <csignal>
#include <sys/resource.h>
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_identity_secret_tests, BasicTestingSetup)

namespace {
fs::path SecretPath(const fs::path& dir, const std::string& id)
{
    return dir / "tls" / fs::PathFromString("identity-" + id.substr(0, 16) + ".sk");
}

struct Helper {
    modelnet::ModelCatalog cat;
    UniValue result;
    std::string code, err;
    explicit Helper(const fs::path& dir) : cat{dir, 8 << 20} {}
    bool Call(const std::string& method, const UniValue& params)
    {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", params);
        result = UniValue(UniValue::VOBJ);
        code.clear();
        err.clear();
        return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    }
    size_t Listed(const std::string& id)
    {
        BOOST_REQUIRE(Call("listmodelidentities", UniValue(UniValue::VARR)));
        size_t n{0};
        if (!result["identities"].isArray()) return 0;
        for (const auto& e : result["identities"].getValues()) n += e["id"].get_str() == id;
        return n;
    }
};
} // namespace

#ifndef WIN32
BOOST_AUTO_TEST_CASE(identity_whose_key_is_cut_short_is_not_listed)
{
    // createmodelidentity listed the identity first and then wrote its secret
    // key without checking the write. A key that a full disk cut short could
    // never sign. RLIMIT_FSIZE below the key size stands in for the full disk.
    const fs::path dir = m_path_root / "identity-key-cut-short";
    Helper helper{dir};
    UniValue first(UniValue::VARR);
    first.push_back("first");
    BOOST_REQUIRE_MESSAGE(helper.Call("createmodelidentity", first), helper.err);
    const std::string first_id = helper.result["id"].get_str();
    BOOST_CHECK_EQUAL(fs::file_size(SecretPath(dir, first_id)), modelnet::MLDSA44_SK);

    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = modelnet::MLDSA44_SK / 2;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    UniValue second(UniValue::VARR);
    second.push_back("second");
    const bool created{helper.Call("createmodelidentity", second)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);

    BOOST_CHECK_MESSAGE(!created, "createmodelidentity reported an identity whose key file was cut short");
    BOOST_CHECK_EQUAL(helper.code, "IO");
    BOOST_REQUIRE(helper.Call("listmodelidentities", UniValue(UniValue::VARR)));
    BOOST_REQUIRE(helper.result["identities"].isArray());
    BOOST_CHECK_EQUAL(helper.result["identities"].size(), 1U);
    BOOST_CHECK_EQUAL(helper.Listed(first_id), 1U);
    for (const auto& entry : fs::directory_iterator(dir / "tls")) {
        const std::string name = fs::PathToString(entry.path().filename());
        BOOST_CHECK_MESSAGE(name == fs::PathToString(SecretPath(dir, first_id).filename()), "left behind: " + name);
    }
}
#endif // WIN32

BOOST_AUTO_TEST_CASE(cut_short_default_identity_key_is_written_again)
{
    // A key file that is not a whole ML-DSA-44 secret key counts as missing,
    // so the default publisher identity writes it again from the research
    // identity, and lists the identity only once.
    const fs::path dir = m_path_root / "identity-key-truncated";
    Helper helper{dir};
    BOOST_REQUIRE(helper.Call("checkmodelsetup", UniValue(UniValue::VARR)));
    BOOST_REQUIRE(helper.result["identity_ready"].get_bool());
    const std::string id = helper.result["identity_id"].get_str();
    const fs::path key = SecretPath(dir, id);
    BOOST_REQUIRE_EQUAL(fs::file_size(key), modelnet::MLDSA44_SK);
    fs::resize_file(key, 100);

    BOOST_REQUIRE(helper.Call("checkmodelsetup", UniValue(UniValue::VARR)));
    BOOST_CHECK(helper.result["identity_ready"].get_bool());
    BOOST_CHECK_EQUAL(helper.result["identity_id"].get_str(), id);
    BOOST_CHECK_EQUAL(fs::file_size(key), modelnet::MLDSA44_SK);
    BOOST_CHECK_EQUAL(helper.Listed(id), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
