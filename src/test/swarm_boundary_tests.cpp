// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_boundary.h>
#include <modelnet/swarm_incident.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_boundary_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_transport_pin_is_not_a_payment_mandate)
{
    std::string err;
    BOOST_CHECK(modelnet::SwarmCapabilityCovers(modelnet::SwarmCapability::TransportPin, modelnet::SwarmCapability::TransportPin, err));
    BOOST_CHECK(!modelnet::SwarmCapabilityCovers(modelnet::SwarmCapability::TransportPin, modelnet::SwarmCapability::PaymentMandate, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK(!modelnet::SwarmCapabilityCovers(modelnet::SwarmCapability::DataGrant, modelnet::SwarmCapability::RoleGrant, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");

    std::string accepted;
    BOOST_CHECK(!modelnet::SwarmTrustLabel("", "self", accepted, err));
    BOOST_CHECK_EQUAL(err, "TRUST_LABEL");
    BOOST_REQUIRE(modelnet::SwarmTrustLabel("realm-a", "somewhere-else", accepted, err));
    BOOST_CHECK_EQUAL(accepted, "realm-a");

    modelnet::SwarmRealmJoin join;
    BOOST_CHECK(!modelnet::SwarmJoinWorkRealm(join, true, err));
    BOOST_CHECK_EQUAL(err, "COMMITTEE");
    BOOST_CHECK(!join.work_realm_joined);
    BOOST_CHECK(!join.controller_committee_joined);
    BOOST_REQUIRE(modelnet::SwarmJoinWorkRealm(join, false, err));
    BOOST_CHECK(join.work_realm_joined);
    BOOST_CHECK(!join.controller_committee_joined);
}

BOOST_AUTO_TEST_CASE(poisoning_freezes_new_work_and_keeps_the_prior_checkpoint)
{
    modelnet::SwarmIncident incident;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmFreezePoisoning(incident, err));
    BOOST_CHECK(incident.frozen);
    BOOST_CHECK(incident.evidence_retained);
    BOOST_CHECK(incident.prior_checkpoint_preserved);
    BOOST_CHECK(incident.new_work_halted);
    BOOST_CHECK(!incident.identity_remapped);

    modelnet::SwarmIncident remap;
    BOOST_CHECK(!modelnet::SwarmNoteKeyCompromise(remap, true, err));
    BOOST_CHECK_EQUAL(err, "IDENTITY_REMAP");
    BOOST_CHECK(!remap.identity_remapped);

    modelnet::SwarmIncident reorg;
    BOOST_REQUIRE(modelnet::SwarmFreezeReorg(reorg, err));
    BOOST_CHECK(reorg.frozen);
    BOOST_CHECK(reorg.earned_kept);
    BOOST_CHECK(reorg.new_work_halted);
}

BOOST_AUTO_TEST_SUITE_END()
