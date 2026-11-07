// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/std_gate/std_gate.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::StdGate& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

void ExpectNoted(modelnet::StdGate& eng, const std::string& name)
{
    std::string err = "stale";
    BOOST_CHECK(!eng.noted(name));
    BOOST_CHECK(eng.Note(name, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.noted(name));
    BOOST_CHECK(!eng.stored(name));
    BOOST_CHECK(!eng.Note(name, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.noted(name));
    BOOST_CHECK(!eng.stored(name));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(std_gate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_or_unknown_name)
{
    modelnet::StdGate eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Note("", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.noted(""));
    BOOST_CHECK(!eng.Note("", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.noted(""));

    BOOST_CHECK(!eng.Note("other", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.noted("other"));
    BOOST_CHECK(!eng.Note("other", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.stored("other"));

    BOOST_CHECK(!eng.Import("", "version", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(!eng.Import("other", "version", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.stored("other"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(six_names_note_and_replay)
{
    modelnet::StdGate eng;
    ExpectNoted(eng, "stix");
    ExpectNoted(eng, "taxii");
    ExpectNoted(eng, "ocsf");
    ExpectNoted(eng, "sigma");
    ExpectNoted(eng, "eve");
    ExpectNoted(eng, "cacao");
    BOOST_CHECK(eng.noted("stix"));
    BOOST_CHECK(eng.noted("taxii"));
    BOOST_CHECK(eng.noted("ocsf"));
    BOOST_CHECK(eng.noted("sigma"));
    BOOST_CHECK(eng.noted("eve"));
    BOOST_CHECK(eng.noted("cacao"));
    BOOST_CHECK(!eng.stored("stix"));
    BOOST_CHECK(!eng.stored("taxii"));
    BOOST_CHECK(!eng.stored("ocsf"));
    BOOST_CHECK(!eng.stored("sigma"));
    BOOST_CHECK(!eng.stored("eve"));
    BOOST_CHECK(!eng.stored("cacao"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(import_refusals_store_nothing)
{
    modelnet::StdGate eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Note("stix", err));
    BOOST_CHECK(eng.Note("taxii", err));
    BOOST_CHECK(eng.Note("ocsf", err));
    BOOST_CHECK(eng.Note("sigma", err));
    BOOST_CHECK(eng.Note("eve", err));
    BOOST_CHECK(eng.Note("cacao", err));

    BOOST_CHECK(!eng.Import("stix", "", err));
    BOOST_CHECK_EQUAL(err, "BODY");
    BOOST_CHECK(!eng.stored("stix"));
    BOOST_CHECK(!eng.Import("taxii", "", err));
    BOOST_CHECK_EQUAL(err, "BODY");
    BOOST_CHECK(!eng.Import("ocsf", "", err));
    BOOST_CHECK_EQUAL(err, "BODY");
    BOOST_CHECK(!eng.Import("sigma", "", err));
    BOOST_CHECK_EQUAL(err, "BODY");
    BOOST_CHECK(!eng.Import("eve", "", err));
    BOOST_CHECK_EQUAL(err, "BODY");
    BOOST_CHECK(!eng.Import("cacao", "", err));
    BOOST_CHECK_EQUAL(err, "BODY");

    BOOST_CHECK(!eng.Import("stix", "bundle", err));
    BOOST_CHECK_EQUAL(err, "VERSION");
    BOOST_CHECK(!eng.stored("stix"));
    BOOST_CHECK(eng.body_of("stix").empty());

    BOOST_CHECK(!eng.Import("taxii", "collection version lineage typed", err));
    BOOST_CHECK_EQUAL(err, "BOUNDED");
    BOOST_CHECK(!eng.stored("taxii"));
    BOOST_CHECK(eng.body_of("taxii").empty());
    BOOST_CHECK(eng.noted("taxii"));

    BOOST_CHECK(!eng.Import("ocsf", "mapped event", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK(!eng.stored("ocsf"));
    BOOST_CHECK(eng.body_of("ocsf").empty());

    BOOST_CHECK(!eng.Import("sigma", "detection rule", err));
    BOOST_CHECK_EQUAL(err, "BACKEND");
    BOOST_CHECK(!eng.stored("sigma"));
    BOOST_CHECK(eng.body_of("sigma").empty());
    BOOST_CHECK(eng.noted("sigma"));

    const std::string beyond(65, 'e');
    BOOST_CHECK(static_cast<int64_t>(beyond.size()) > static_cast<int64_t>(64));
    BOOST_CHECK(!eng.Import("eve", beyond, err));
    BOOST_CHECK_EQUAL(err, "OVERSIZE");
    BOOST_CHECK(!eng.stored("eve"));
    BOOST_CHECK(eng.body_of("eve").empty());

    BOOST_CHECK(!eng.Import("cacao", "playbook", err));
    BOOST_CHECK_EQUAL(err, "SUBSET");
    BOOST_CHECK(!eng.stored("cacao"));
    BOOST_CHECK(eng.body_of("cacao").empty());

    BOOST_CHECK(!eng.stored("stix"));
    BOOST_CHECK(!eng.stored("taxii"));
    BOOST_CHECK(!eng.stored("ocsf"));
    BOOST_CHECK(!eng.stored("sigma"));
    BOOST_CHECK(!eng.stored("eve"));
    BOOST_CHECK(!eng.stored("cacao"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(import_accepts_marked_bodies)
{
    modelnet::StdGate eng;
    std::string err = "stale";
    const std::string stix_body = "bundle version 2.1";
    const std::string ocsf_body = "mapped event lineage";
    const std::string eve_body(64, 'e');
    const std::string cacao_body = "typed playbook";
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eve_body.size()), static_cast<int64_t>(64));

    BOOST_CHECK(eng.Import("stix", stix_body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("stix"));
    BOOST_CHECK_EQUAL(eng.body_of("stix"), stix_body);

    BOOST_CHECK(!eng.Import("stix", "bundle", err));
    BOOST_CHECK_EQUAL(err, "VERSION");
    BOOST_CHECK_EQUAL(eng.body_of("stix"), stix_body);

    std::string wide(80, 's');
    wide.replace(0, 7, "version");
    BOOST_CHECK(static_cast<int64_t>(wide.size()) > static_cast<int64_t>(64));
    BOOST_CHECK(eng.Import("stix", wide, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body_of("stix"), wide);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Import("taxii", "collection", err));
    BOOST_CHECK_EQUAL(err, "BOUNDED");
    BOOST_CHECK(!eng.stored("taxii"));

    BOOST_CHECK(eng.Import("ocsf", ocsf_body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("ocsf"));
    BOOST_CHECK_EQUAL(eng.body_of("ocsf"), ocsf_body);
    BOOST_CHECK(!eng.Import("ocsf", "mapped event", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK_EQUAL(eng.body_of("ocsf"), ocsf_body);

    BOOST_CHECK(!eng.Import("sigma", "detection rule", err));
    BOOST_CHECK_EQUAL(err, "BACKEND");
    BOOST_CHECK(!eng.stored("sigma"));

    BOOST_CHECK(eng.Import("eve", eve_body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("eve"));
    BOOST_CHECK_EQUAL(eng.body_of("eve"), eve_body);
    const std::string beyond(65, 'x');
    BOOST_CHECK(static_cast<int64_t>(beyond.size()) > static_cast<int64_t>(64));
    BOOST_CHECK(!eng.Import("eve", beyond, err));
    BOOST_CHECK_EQUAL(err, "OVERSIZE");
    BOOST_CHECK_EQUAL(eng.body_of("eve"), eve_body);

    BOOST_CHECK(eng.Import("cacao", cacao_body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("cacao"));
    BOOST_CHECK_EQUAL(eng.body_of("cacao"), cacao_body);
    BOOST_CHECK(!eng.Import("cacao", "playbook", err));
    BOOST_CHECK_EQUAL(err, "SUBSET");
    BOOST_CHECK_EQUAL(eng.body_of("cacao"), cacao_body);

    BOOST_CHECK(!eng.stored("taxii"));
    BOOST_CHECK(!eng.stored("sigma"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(release_stays_unqualified)
{
    modelnet::StdGate eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());

    BOOST_CHECK(eng.Note("stix", err));
    BOOST_CHECK(eng.Note("taxii", err));
    BOOST_CHECK(eng.Note("ocsf", err));
    BOOST_CHECK(eng.Note("sigma", err));
    BOOST_CHECK(eng.Note("eve", err));
    BOOST_CHECK(eng.Note("cacao", err));
    BOOST_CHECK(eng.noted("stix"));
    BOOST_CHECK(eng.noted("taxii"));
    BOOST_CHECK(eng.noted("ocsf"));
    BOOST_CHECK(eng.noted("sigma"));
    BOOST_CHECK(eng.noted("eve"));
    BOOST_CHECK(eng.noted("cacao"));

    BOOST_CHECK(eng.Import("stix", "version", err));
    BOOST_CHECK(eng.Import("ocsf", "lineage", err));
    const std::string eve_body(64, 'e');
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eve_body.size()), static_cast<int64_t>(64));
    BOOST_CHECK(eng.Import("eve", eve_body, err));
    BOOST_CHECK(eng.Import("cacao", "typed", err));
    BOOST_CHECK(!eng.Import("taxii", "collection", err));
    BOOST_CHECK_EQUAL(err, "BOUNDED");
    BOOST_CHECK(!eng.Import("sigma", "detection", err));
    BOOST_CHECK_EQUAL(err, "BACKEND");

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(eng.noted("stix"));
    BOOST_CHECK(eng.noted("taxii"));
    BOOST_CHECK(eng.noted("ocsf"));
    BOOST_CHECK(eng.noted("sigma"));
    BOOST_CHECK(eng.noted("eve"));
    BOOST_CHECK(eng.noted("cacao"));
    BOOST_CHECK(eng.stored("stix"));
    BOOST_CHECK(!eng.stored("taxii"));
    BOOST_CHECK(eng.stored("ocsf"));
    BOOST_CHECK(!eng.stored("sigma"));
    BOOST_CHECK(eng.stored("eve"));
    BOOST_CHECK(eng.stored("cacao"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
