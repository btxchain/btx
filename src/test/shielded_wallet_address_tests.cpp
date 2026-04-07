// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <crypto/sha256.h>
#include <test/util/setup_common.h>
#include <wallet/shielded_wallet.h>

#include <algorithm>
#include <set>
#include <boost/test/unit_test.hpp>

using wallet::ShieldedAddress;

BOOST_FIXTURE_TEST_SUITE(shielded_wallet_address_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shielded_address_roundtrip)
{
    ShieldedAddress addr;
    addr.version = 0x01;
    addr.algo_byte = 0x00;
    addr.pk_hash = GetRandHash();
    for (size_t offset = 0; offset < addr.kem_pk.size();) {
        const size_t chunk = std::min<size_t>(32, addr.kem_pk.size() - offset);
        GetStrongRandBytes(Span<unsigned char>{addr.kem_pk.data() + offset, chunk});
        offset += chunk;
    }
    CSHA256().Write(addr.kem_pk.data(), addr.kem_pk.size()).Finalize(addr.kem_pk_hash.begin());

    const std::string encoded = addr.Encode();
    const auto decoded = ShieldedAddress::Decode(encoded);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == addr);
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded->kem_pk.begin(), decoded->kem_pk.end(), addr.kem_pk.begin(), addr.kem_pk.end());
    BOOST_CHECK(decoded->HasKEMPublicKey());
    BOOST_CHECK(decoded->IsValid());
}

BOOST_AUTO_TEST_CASE(shielded_address_legacy_roundtrip)
{
    ShieldedAddress addr;
    addr.version = 0x00;
    addr.algo_byte = 0x00;
    addr.pk_hash = GetRandHash();
    addr.kem_pk_hash = GetRandHash();

    const std::string encoded = addr.Encode();
    const auto decoded = ShieldedAddress::Decode(encoded);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == addr);
    BOOST_CHECK(!decoded->HasKEMPublicKey());
    BOOST_CHECK(decoded->IsValid());
}

BOOST_AUTO_TEST_CASE(shielded_address_decode_rejects_invalid)
{
    BOOST_CHECK(!ShieldedAddress::Decode("not-a-valid-shielded-address").has_value());

    ShieldedAddress addr;
    addr.pk_hash = GetRandHash();
    addr.kem_pk_hash = GetRandHash();
    const std::string encoded = addr.Encode();

    std::string mutated = encoded;
    mutated[0] = (mutated[0] == 'b') ? 'c' : 'b';
    BOOST_CHECK(!ShieldedAddress::Decode(mutated).has_value());
}

BOOST_AUTO_TEST_CASE(shielded_address_ordering_distinguishes_all_identity_fields)
{
    ShieldedAddress base;
    base.version = 0x01;
    base.algo_byte = 0x00;
    base.pk_hash = GetRandHash();
    base.kem_pk_hash = GetRandHash();

    ShieldedAddress diff_version = base;
    diff_version.version = 0x00;

    ShieldedAddress diff_algo = base;
    diff_algo.algo_byte = 0x7f;

    std::set<ShieldedAddress> ordered;
    ordered.insert(base);
    ordered.insert(diff_version);
    ordered.insert(diff_algo);

    BOOST_CHECK_EQUAL(ordered.size(), 3U);
}

BOOST_AUTO_TEST_SUITE_END()
