// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/crypto.h>
#include <modelnet/identity.h>
#include <modelnet/pq_transport_binding.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_transport_tests, BasicTestingSetup)

namespace {

std::string Hex96(char digit)
{
    return std::string(96, digit);
}

std::vector<unsigned char> TransportPk(unsigned char fill)
{
    return std::vector<unsigned char>(modelnet::MLDSA44_PK, fill);
}

modelnet::Digest48 ExpectedBindingId(const std::vector<unsigned char>& pk)
{
    std::vector<unsigned char> body;
    body.reserve(1 + pk.size());
    body.push_back(0x01);
    body.insert(body.end(), pk.begin(), pk.end());
    return modelnet::DomainHash("BTX/035/TransportBinding/v1.1", body);
}

} // namespace

BOOST_AUTO_TEST_CASE(supported_pq1_profile_accepts_only_strict_suite)
{
    std::string err = "stale";
    BOOST_CHECK(modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(supported_pq1_profile_rejects_classical_empty_and_aliases)
{
    const char* classical[] = {"x25519", "X25519", "secp256r1", "ecdsa", "rsa", "x25519_mlkem768"};
    for (const char* name : classical) {
        std::string err;
        BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", name, "TLS_AES_256_GCM_SHA384", "mldsa44", err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
        err.clear();
        BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", name, "mldsa44", err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
        err.clear();
        BOOST_CHECK(!modelnet::SupportedPq1Profile(name, "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
        err.clear();
        BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", name, err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    }

    std::string err;
    BOOST_CHECK(!modelnet::SupportedPq1Profile("", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", "", "mldsa44", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");

    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.2", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "MLKEM768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", "TLS_AES_128_GCM_SHA256", "mldsa44", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::SupportedPq1Profile("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "ecdsa_secp256r1_sha256", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
}

BOOST_AUTO_TEST_CASE(bind_transport_key_domain_hashes_prefixed_pk)
{
    const std::string root = Hex96('a');
    const std::vector<unsigned char> pk = TransportPk(0x5a);
    modelnet::TransportBindingRecord binding;
    std::string err = "stale";
    BOOST_REQUIRE(modelnet::BindTransportKey(root, pk, binding, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(binding.research_root_hex, root);
    BOOST_CHECK(binding.transport_pk == pk);
    BOOST_CHECK(binding.binding_id == ExpectedBindingId(pk));
    BOOST_CHECK(binding.transport_identity == modelnet::ResearchIdentityId(pk));
    BOOST_CHECK(binding.binding_id != binding.transport_identity);
    BOOST_CHECK(binding.binding_id != modelnet::DomainHash("BTX/035/TransportBinding/v1.1", pk));

    const std::vector<unsigned char> other = TransportPk(0x5b);
    modelnet::TransportBindingRecord binding_b;
    BOOST_REQUIRE(modelnet::BindTransportKey(root, other, binding_b, err));
    BOOST_CHECK(binding.binding_id != binding_b.binding_id);
}

BOOST_AUTO_TEST_CASE(bind_transport_key_rejects_bad_length_and_root)
{
    const std::string root = Hex96('b');
    modelnet::TransportBindingRecord binding;
    std::string err;
    std::vector<unsigned char> short_pk(modelnet::MLDSA44_PK - 1, 0x01);
    BOOST_CHECK(!modelnet::BindTransportKey(root, short_pk, binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_KEY_LENGTH");
    BOOST_CHECK(binding.transport_pk.empty());

    std::vector<unsigned char> long_pk(modelnet::MLDSA44_PK + 1, 0x02);
    BOOST_CHECK(!modelnet::BindTransportKey(root, long_pk, binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_KEY_LENGTH");

    BOOST_CHECK(!modelnet::BindTransportKey(root, std::vector<unsigned char>{}, binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_KEY_LENGTH");

    const std::vector<unsigned char> pk = TransportPk(0x11);
    BOOST_CHECK(!modelnet::BindTransportKey("", pk, binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BINDING_INVALID");
    BOOST_CHECK(!modelnet::BindTransportKey(std::string(95, 'a'), pk, binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BINDING_INVALID");
    BOOST_CHECK(!modelnet::BindTransportKey(std::string(96, 'A'), pk, binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BINDING_INVALID");
    BOOST_CHECK(binding.transport_pk.empty());
}

BOOST_AUTO_TEST_CASE(substitute_transport_rejects_a_different_key)
{
    const std::vector<unsigned char> pk = TransportPk(0x22);
    modelnet::TransportBindingRecord binding;
    std::string err;
    BOOST_REQUIRE(modelnet::BindTransportKey(Hex96('c'), pk, binding, err));

    BOOST_CHECK(modelnet::SubstituteTransport(binding, pk, err));
    BOOST_CHECK(err.empty());

    std::vector<unsigned char> swapped = pk;
    swapped.back() = static_cast<unsigned char>(swapped.back() ^ 0xff);
    BOOST_CHECK(!modelnet::SubstituteTransport(binding, swapped, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TRANSPORT_SUBSTITUTE");

    BOOST_CHECK(!modelnet::SubstituteTransport(binding, std::vector<unsigned char>{}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TRANSPORT_SUBSTITUTE");

    std::vector<unsigned char> short_pk(pk.begin(), pk.end() - 1);
    BOOST_CHECK(!modelnet::SubstituteTransport(binding, short_pk, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TRANSPORT_SUBSTITUTE");

    modelnet::TransportBindingRecord empty;
    BOOST_CHECK(!modelnet::SubstituteTransport(empty, std::vector<unsigned char>{}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TRANSPORT_SUBSTITUTE");
}

BOOST_AUTO_TEST_CASE(session_proof_accepts_bound_root_once)
{
    const std::string root = Hex96('d');
    const std::vector<unsigned char> pk = TransportPk(0x33);
    modelnet::TransportBindingRecord binding;
    std::string err;
    BOOST_REQUIRE(modelnet::BindTransportKey(root, pk, binding, err));

    modelnet::SessionProofStore store;
    BOOST_REQUIRE(store.Bind(binding, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(store.Accept("conn-1", "nonce-1", root, 1700000000000, err));
    BOOST_CHECK(err.empty());
    int64_t seen = 0;
    BOOST_CHECK(store.AcceptedMs("conn-1", "nonce-1", seen));
    BOOST_CHECK_EQUAL(seen, 1700000000000);

    BOOST_CHECK(store.Accept("conn-1", "nonce-2", root, 1700000000001, err));
    BOOST_CHECK(store.Accept("conn-2", "nonce-1", root, 1700000000002, err));
}

BOOST_AUTO_TEST_CASE(session_proof_rejects_empty_replay_and_unbound)
{
    const std::string root = Hex96('e');
    const std::vector<unsigned char> pk = TransportPk(0x44);
    modelnet::TransportBindingRecord binding;
    std::string err;
    BOOST_REQUIRE(modelnet::BindTransportKey(root, pk, binding, err));

    modelnet::SessionProofStore store;
    BOOST_CHECK(!store.Accept("conn", "nonce", root, 10, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNBOUND");
    BOOST_CHECK(!store.Accept("conn", "nonce", root, 11, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNBOUND");

    BOOST_CHECK(!store.Accept("", "nonce", root, 12, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SESSION");
    BOOST_CHECK(!store.Accept("conn", "", root, 13, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SESSION");
    BOOST_CHECK(!store.Accept("", "", root, 14, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SESSION");

    BOOST_REQUIRE(store.Bind(binding, err));
    BOOST_CHECK(!store.Accept("", "nonce", root, 15, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SESSION");

    BOOST_CHECK(store.Accept("conn", "nonce", root, 16, err));
    BOOST_CHECK(!store.Accept("conn", "nonce", root, 17, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
    BOOST_CHECK(!store.Accept("conn", "nonce", Hex96('f'), 18, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");

    BOOST_CHECK(!store.Accept("conn", "other-nonce", Hex96('f'), 19, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNBOUND");

    binding.transport_identity = binding.binding_id;
    BOOST_CHECK(!store.Bind(binding, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BINDING_INVALID");
}

BOOST_AUTO_TEST_CASE(recipient_matches_equal_lowercase_digest)
{
    const std::string id = Hex96('1');
    std::string err = "stale";
    BOOST_CHECK(modelnet::RecipientMatches(id, id, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(recipient_rejects_mismatch_case_and_length)
{
    const std::string id = Hex96('a');
    std::string other = id;
    other.back() = 'b';
    std::string err;
    BOOST_CHECK(!modelnet::RecipientMatches(id, other, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");

    std::string upper = id;
    upper[0] = 'A';
    BOOST_CHECK(!modelnet::RecipientMatches(upper, upper, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");
    BOOST_CHECK(!modelnet::RecipientMatches(id, upper, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");

    BOOST_CHECK(!modelnet::RecipientMatches(id, id.substr(1), err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");
    BOOST_CHECK(!modelnet::RecipientMatches("", "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");
    BOOST_CHECK(!modelnet::RecipientMatches(id, "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");

    std::string bad = id;
    bad[10] = 'g';
    BOOST_CHECK(!modelnet::RecipientMatches(bad, bad, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECIPIENT");
}

BOOST_AUTO_TEST_SUITE_END()
