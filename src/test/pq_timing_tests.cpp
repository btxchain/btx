// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/ct_utils.h>
#include <hash.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <vector>

namespace {

double CoefficientOfVariation(const std::vector<int64_t>& samples)
{
    if (samples.empty()) return 0.0;
    double mean{0.0};
    for (const auto sample : samples) mean += static_cast<double>(sample);
    mean /= static_cast<double>(samples.size());
    if (mean <= 0.0) return 0.0;

    double variance{0.0};
    for (const auto sample : samples) {
        const double delta = static_cast<double>(sample) - mean;
        variance += delta * delta;
    }
    variance /= static_cast<double>(samples.size());
    return std::sqrt(variance) / mean;
}

double Mean(const std::vector<int64_t>& samples)
{
    if (samples.empty()) return 0.0;
    double sum{0.0};
    for (const auto sample : samples) sum += static_cast<double>(sample);
    return sum / static_cast<double>(samples.size());
}

double Median(std::vector<double> samples)
{
    if (samples.empty()) return 0.0;
    std::sort(samples.begin(), samples.end());
    const size_t mid = samples.size() / 2;
    if (samples.size() % 2 == 1) return samples[mid];
    return (samples[mid - 1] + samples[mid]) * 0.5;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_timing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mldsa_sign_constant_time)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    // Warm-up to reduce one-time setup noise.
    for (uint32_t i = 0; i < 10; ++i) {
        const uint256 msg = (HashWriter{} << i << 0xA5U).GetSHA256();
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(msg, sig));
    }

    // Batch several operations per sample so scheduler jitter does not dominate
    // the variance metric on busy CI machines.
    std::vector<int64_t> timings;
    constexpr uint32_t SAMPLE_BATCHES{64};
    constexpr uint32_t OPS_PER_BATCH{4};
    timings.reserve(SAMPLE_BATCHES);
    for (uint32_t batch = 0; batch < SAMPLE_BATCHES; ++batch) {
        const auto start = std::chrono::steady_clock::now();
        for (uint32_t op = 0; op < OPS_PER_BATCH; ++op) {
            const uint32_t i = batch * OPS_PER_BATCH + op;
            const uint256 msg = (HashWriter{} << i).GetSHA256();
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(key.Sign(msg, sig));
            BOOST_CHECK_EQUAL(sig.size(), MLDSA44_SIGNATURE_SIZE);
        }
        const auto end = std::chrono::steady_clock::now();
        timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
    }
    const double cv = CoefficientOfVariation(timings);
    BOOST_TEST_CONTEXT("mldsa_sign_cv=" << cv) {
        BOOST_CHECK_LT(cv, 1.10);
    }
}

BOOST_AUTO_TEST_CASE(mldsa_verify_constant_time)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    CPQPubKey pub(PQAlgorithm::ML_DSA_44, key.GetPubKey());

    // Warm-up to reduce one-time setup noise.
    for (uint32_t i = 0; i < 10; ++i) {
        const uint256 msg = (HashWriter{} << i << 0x5aU << 0xC3U).GetSHA256();
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(msg, sig));
        BOOST_REQUIRE(pub.Verify(msg, sig));
    }

    constexpr uint32_t SAMPLE_BATCHES{64};
    constexpr uint32_t OPS_PER_BATCH{4};
    const uint32_t total_ops = SAMPLE_BATCHES * OPS_PER_BATCH;
    std::vector<uint256> messages;
    messages.reserve(total_ops);
    std::vector<std::vector<unsigned char>> signatures;
    signatures.reserve(total_ops);
    for (uint32_t i = 0; i < total_ops; ++i) {
        const uint256 msg = (HashWriter{} << i << 0x5aU).GetSHA256();
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(msg, sig));
        messages.push_back(msg);
        signatures.push_back(std::move(sig));
    }

    // Batch several verifies per sample to suppress scheduler-noise outliers.
    std::vector<int64_t> timings;
    timings.reserve(SAMPLE_BATCHES);
    for (uint32_t batch = 0; batch < SAMPLE_BATCHES; ++batch) {
        const auto start = std::chrono::steady_clock::now();
        for (uint32_t op = 0; op < OPS_PER_BATCH; ++op) {
            const uint32_t i = batch * OPS_PER_BATCH + op;
            BOOST_CHECK(pub.Verify(messages[i], signatures[i]));
        }
        const auto end = std::chrono::steady_clock::now();
        timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
    }
    const double cv = CoefficientOfVariation(timings);
    BOOST_TEST_CONTEXT("mldsa_verify_cv=" << cv) {
        BOOST_CHECK_LT(cv, 1.10);
    }
}

BOOST_AUTO_TEST_CASE(key_comparison_constant_time)
{
    std::vector<unsigned char> a(256, 0x11);
    std::vector<unsigned char> b(256, 0x11);
    std::vector<unsigned char> c = b;
    c.back() = 0x12;

    BOOST_CHECK_EQUAL(ct_memcmp(a.data(), b.data(), a.size()), 0);
    BOOST_CHECK_NE(ct_memcmp(a.data(), c.data(), a.size()), 0);

    constexpr int SAMPLE_BATCHES{120};
    constexpr int BATCH_ITERS{4000};

    std::vector<int64_t> first_mismatch_timing;
    std::vector<int64_t> last_mismatch_timing;
    first_mismatch_timing.reserve(SAMPLE_BATCHES);
    last_mismatch_timing.reserve(SAMPLE_BATCHES);
    std::vector<double> per_pair_rel_delta;
    per_pair_rel_delta.reserve(SAMPLE_BATCHES);

    std::vector<unsigned char> first_mismatch = b;
    std::vector<unsigned char> last_mismatch = b;
    first_mismatch[0] ^= 1;
    last_mismatch.back() ^= 1;

    const auto MeasureBatch = [&](const std::vector<unsigned char>& other) {
        const auto start = std::chrono::steady_clock::now();
        for (int j = 0; j < BATCH_ITERS; ++j) {
            (void)ct_memcmp(a.data(), other.data(), a.size());
        }
        const auto end = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    };

    // Interleave first/last mismatch probes to cancel thermal/scheduler drift.
    for (int i = 0; i < SAMPLE_BATCHES; ++i) {
        int64_t first_ns{0};
        int64_t last_ns{0};
        if ((i % 2) == 0) {
            first_ns = MeasureBatch(first_mismatch);
            last_ns = MeasureBatch(last_mismatch);
        } else {
            last_ns = MeasureBatch(last_mismatch);
            first_ns = MeasureBatch(first_mismatch);
        }
        first_mismatch_timing.push_back(first_ns);
        last_mismatch_timing.push_back(last_ns);
        const double denom = static_cast<double>(std::max(first_ns, last_ns));
        per_pair_rel_delta.push_back(denom > 0.0 ? std::abs(static_cast<double>(first_ns - last_ns)) / denom : 0.0);
    }

    const double first_mean = Mean(first_mismatch_timing);
    const double last_mean = Mean(last_mismatch_timing);
    const double rel_delta = (std::max(first_mean, last_mean) > 0.0)
        ? std::abs(first_mean - last_mean) / std::max(first_mean, last_mean)
        : 0.0;
    const double median_pair_rel_delta = Median(per_pair_rel_delta);
    BOOST_TEST_CONTEXT("first_mean=" << first_mean
                       << ", last_mean=" << last_mean
                       << ", rel_delta=" << rel_delta
                       << ", median_pair_rel_delta=" << median_pair_rel_delta) {
        BOOST_CHECK_LT(rel_delta, 0.40);
        BOOST_CHECK_LT(median_pair_rel_delta, 0.40);
    }
}

BOOST_AUTO_TEST_CASE(key_zeroization_complete)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    BOOST_REQUIRE(!key.GetPubKey().empty());

    key.ClearKeyData();
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK(key.GetPubKey().empty());

    std::vector<unsigned char> sig;
    BOOST_CHECK(!key.Sign(uint256{1}, sig));
    BOOST_CHECK(sig.empty());
}

BOOST_AUTO_TEST_SUITE_END()
