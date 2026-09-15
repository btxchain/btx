// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>

#include <modelnet/firstrun.h>
#include <modelnet/policy.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <optional>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_firstrun_tests, BasicTestingSetup)

namespace {

class EnvRestore
{
public:
    explicit EnvRestore(std::string key) : m_key(std::move(key))
    {
        if (const char* v = std::getenv(m_key.c_str())) {
            m_prev = std::string{v};
        }
    }
    ~EnvRestore()
    {
        if (m_prev) {
            setenv(m_key.c_str(), m_prev->c_str(), 1);
        } else {
            unsetenv(m_key.c_str());
        }
    }
    void Set(const char* v) { setenv(m_key.c_str(), v, 1); }
    void Unset() { unsetenv(m_key.c_str()); }

private:
    std::string m_key;
    std::optional<std::string> m_prev;
};

void CheckBudgetToken(const std::string& in, uint64_t expected)
{
    uint64_t via_storage = 0;
    uint64_t via_model = 0;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseStorageBudget(in, via_storage, err), err);
    BOOST_CHECK_EQUAL(via_storage, expected);
    BOOST_REQUIRE_MESSAGE(modelnet::ParseModelBytes(in, via_model, err), err);
    BOOST_CHECK_EQUAL(via_model, expected);
}

} // namespace

BOOST_AUTO_TEST_CASE(firstrun_consent_path)
{
    const fs::path datadir = m_path_root / "firstrun-path";
    BOOST_CHECK_EQUAL(fs::PathToString(modelnet::FirstRunConsentPath(datadir)),
                      fs::PathToString(datadir / "modelnet" / "firstrun.json"));
}

BOOST_AUTO_TEST_CASE(save_load_roundtrip_storage_seed_preserve_rare)
{
    const fs::path datadir = m_path_root / "firstrun-roundtrip";
    const fs::path path = modelnet::FirstRunConsentPath(datadir);
    std::string err;

    modelnet::FirstRunConsent auto_in;
    auto_in.storage_bytes = 80ULL << 30;
    auto_in.seed = modelnet::SeedMode::AUTO;
    auto_in.preserve_rare = true;
    auto_in.consented_unix = 1'700'000'000;
    BOOST_REQUIRE_MESSAGE(modelnet::SaveFirstRunConsent(path, auto_in, err), err);

    modelnet::FirstRunConsent auto_out;
    BOOST_REQUIRE_MESSAGE(modelnet::LoadFirstRunConsent(path, auto_out, err), err);
    BOOST_CHECK_EQUAL(auto_out.storage_bytes, auto_in.storage_bytes);
    BOOST_CHECK(auto_out.seed == modelnet::SeedMode::AUTO);
    BOOST_CHECK(auto_out.preserve_rare);
    BOOST_CHECK_EQUAL(auto_out.consented_unix, auto_in.consented_unix);

    modelnet::FirstRunConsent off_in;
    off_in.storage_bytes = 500ULL << 30;
    off_in.seed = modelnet::SeedMode::OFF;
    off_in.preserve_rare = false;
    off_in.consented_unix = 1'800'000'000;
    BOOST_REQUIRE_MESSAGE(modelnet::SaveFirstRunConsent(path, off_in, err), err);

    modelnet::FirstRunConsent off_out;
    BOOST_REQUIRE_MESSAGE(modelnet::LoadFirstRunConsent(path, off_out, err), err);
    BOOST_CHECK_EQUAL(off_out.storage_bytes, off_in.storage_bytes);
    BOOST_CHECK(off_out.seed == modelnet::SeedMode::OFF);
    BOOST_CHECK(!off_out.preserve_rare);
    BOOST_CHECK_EQUAL(off_out.consented_unix, off_in.consented_unix);
}

BOOST_AUTO_TEST_CASE(allow_payload_storage)
{
    modelnet::FirstRunConsent zero;
    zero.storage_bytes = 0;
    BOOST_CHECK(!modelnet::AllowPayloadStorage(zero));

    modelnet::FirstRunConsent positive;
    positive.storage_bytes = 1;
    BOOST_CHECK(modelnet::AllowPayloadStorage(positive));

    const fs::path path = modelnet::FirstRunConsentPath(m_path_root / "firstrun-allow");
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::SaveFirstRunConsent(path, zero, err), err);
    BOOST_CHECK(!modelnet::AllowPayloadStorageFile(path));
    BOOST_REQUIRE_MESSAGE(modelnet::SaveFirstRunConsent(path, positive, err), err);
    BOOST_CHECK(modelnet::AllowPayloadStorageFile(path));
}

BOOST_AUTO_TEST_CASE(parse_storage_budget_and_model_bytes)
{
    CheckBudgetToken("80GiB", 80ULL << 30);
    CheckBudgetToken("500G", 500ULL << 30);
    CheckBudgetToken("0", 0);
}

BOOST_AUTO_TEST_CASE(env_has_positive_storage_budget)
{
    EnvRestore env{"BTX_MODEL_STORAGE"};
    uint64_t bytes = 99;
    std::string err;

    env.Unset();
    BOOST_CHECK(!modelnet::EnvHasPositiveStorageBudget(bytes, err));
    BOOST_CHECK_EQUAL(bytes, 0);

    env.Set("");
    bytes = 99;
    BOOST_CHECK(!modelnet::EnvHasPositiveStorageBudget(bytes, err));
    BOOST_CHECK_EQUAL(bytes, 0);

    env.Set("0");
    bytes = 99;
    BOOST_CHECK(!modelnet::EnvHasPositiveStorageBudget(bytes, err));
    BOOST_CHECK_EQUAL(bytes, 0);

    env.Set("80GiB");
    bytes = 0;
    BOOST_REQUIRE_MESSAGE(modelnet::EnvHasPositiveStorageBudget(bytes, err), err);
    BOOST_CHECK_EQUAL(bytes, 80ULL << 30);
}

BOOST_AUTO_TEST_SUITE_END()
