// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_egress/nif_egress.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(const modelnet::NifEgress& egress)
{
    BOOST_CHECK(!egress.launched());
    BOOST_CHECK(!egress.gpu());
    BOOST_CHECK(!egress.broadcast());
    BOOST_CHECK(!egress.qualified());
    BOOST_CHECK_EQUAL(egress.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(egress.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(egress.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(egress.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(nif_egress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bad_scope_keeps_the_previous_scope)
{
    modelnet::NifEgress egress;
    std::string err = "prior";

    BOOST_CHECK_EQUAL(egress.scope(), "local");
    BOOST_CHECK(!egress.airgap());
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!egress.SetScope("wan", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_EGRESS_SCOPE);
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(egress.scope(), "local");

    BOOST_CHECK(!egress.SetScope("", err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(egress.scope(), "local");

    BOOST_CHECK(egress.SetScope("peer", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(egress.scope(), "peer");

    BOOST_CHECK(!egress.SetScope("internet", err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(egress.scope(), "peer");

    BOOST_CHECK(egress.SetScope("lan", err));
    BOOST_CHECK_EQUAL(egress.scope(), "lan");
    BOOST_CHECK(egress.SetScope("local", err));
    BOOST_CHECK_EQUAL(egress.scope(), "local");
    Idle(egress);
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(local_send_stores_three_bytes)
{
    modelnet::NifEgress egress;
    std::string err = "prior";
    const std::vector<unsigned char> payload{1, 2, 3};

    BOOST_CHECK_EQUAL(egress.scope(), "local");
    BOOST_CHECK(egress.Send(payload, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(egress.received() == payload);
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!egress.Send({}, err));
    BOOST_CHECK_EQUAL(err, "PAYLOAD");
    BOOST_CHECK(egress.received() == payload);
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));
    Idle(egress);
}

BOOST_AUTO_TEST_CASE(lan_exchange_reports_four_wire_bytes)
{
    modelnet::NifEgress egress;
    std::string err = "prior";
    const std::vector<unsigned char> payload{1, 2, 3, 4};

    BOOST_CHECK(egress.SetScope("lan", err));
    BOOST_CHECK_EQUAL(egress.scope(), "lan");
    BOOST_CHECK(!egress.Send({}, err));
    BOOST_CHECK_EQUAL(err, "PAYLOAD");
    BOOST_CHECK(egress.received().empty());
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(egress.Send(payload, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(egress.received() == payload);
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(payload.size()));
    Idle(egress);
}

BOOST_AUTO_TEST_CASE(peer_exchange_uses_the_same_wire)
{
    modelnet::NifEgress egress;
    std::string err;
    const std::vector<unsigned char> payload{5, 6};

    BOOST_CHECK(egress.SetScope("peer", err));
    BOOST_CHECK(egress.Send(payload, err));
    BOOST_CHECK(egress.received() == payload);
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(payload.size()));
    BOOST_CHECK_EQUAL(egress.scope(), "peer");
    Idle(egress);
}

BOOST_AUTO_TEST_CASE(wan_is_no_route_and_does_not_broaden_scope)
{
    modelnet::NifEgress egress;
    std::string err = "prior";

    BOOST_CHECK(!egress.SendWan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(egress.scope(), "local");
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!egress.SendWan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(egress.scope(), "local");

    BOOST_CHECK(egress.SetScope("lan", err));
    BOOST_CHECK(!egress.SendWan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(egress.scope(), "lan");
    BOOST_CHECK(!egress.SendWan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(egress.scope(), "lan");
    Idle(egress);
}

BOOST_AUTO_TEST_CASE(scan_is_not_scan)
{
    modelnet::NifEgress egress;
    std::string err = "prior";

    BOOST_CHECK(!egress.Scan("prefix", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NOT_SCAN);
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK_EQUAL(egress.scope(), "local");
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(egress.received().empty());
    Idle(egress);
}

BOOST_AUTO_TEST_CASE(airgap_blocks_a_later_lan_send)
{
    modelnet::NifEgress egress;
    std::string err = "prior";
    const std::vector<unsigned char> payload{1, 2, 3, 4};

    BOOST_CHECK(egress.SetScope("lan", err));
    egress.SetAirgap(true);
    BOOST_CHECK(egress.airgap());
    BOOST_CHECK_EQUAL(egress.scope(), "lan");

    BOOST_CHECK(!egress.Send(payload, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_EGRESS_POLICY);
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK(egress.received().empty());
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(egress.scope(), "lan");
    BOOST_CHECK(egress.airgap());

    egress.SetAirgap(false);
    BOOST_CHECK(!egress.airgap());
    BOOST_CHECK_EQUAL(egress.scope(), "lan");
    BOOST_CHECK(egress.Send(payload, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(egress.received() == payload);
    BOOST_CHECK_EQUAL(egress.bytes_moved(), static_cast<int64_t>(4));
    Idle(egress);
}

BOOST_AUTO_TEST_SUITE_END()
