// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_v4_rc_fp3_lde_gpu.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_fp3_lde_gpu_tests, BasicTestingSetup)

namespace {

constexpr gf::Fp kOmega2_32 = UINT64_C(0x185629dcda58878c);

gf::Fp PowFp(gf::Fp base, uint64_t exponent)
{
    gf::Fp result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) result = gf::Mul(result, base);
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return result;
}

uint32_t Log2Exact(uint32_t n)
{
    uint32_t log_n = 0;
    while (n > 1) {
        n >>= 1;
        ++log_n;
    }
    return log_n;
}

gf::Fp OmegaForSize(uint32_t n)
{
    if (n == 1) return 1;
    return PowFp(kOmega2_32,
                 uint64_t{1} << (32 - Log2Exact(n)));
}

struct RootTables {
    std::vector<uint64_t> forward;
    std::vector<uint64_t> inverse;
    uint64_t inverse_n{1};
};

RootTables MakeRootTables(uint32_t n)
{
    RootTables out;
    out.inverse_n = gf::Inv(n);
    if (n == 1) return out;
    const gf::Fp omega = OmegaForSize(n);
    const gf::Fp omega_inverse = gf::Inv(omega);
    out.forward.resize(n / 2);
    out.inverse.resize(n / 2);
    gf::Fp f = 1;
    gf::Fp i = 1;
    for (uint32_t j = 0; j < n / 2; ++j) {
        out.forward[j] = f;
        out.inverse[j] = i;
        f = gf::Mul(f, omega);
        i = gf::Mul(i, omega_inverse);
    }
    return out;
}

struct ContextDeleter {
    void operator()(void* ptr) const { BtxGpuFp3LdeRelease(ptr); }
};
using Context = std::unique_ptr<void, ContextDeleter>;

Context MakeContext(uint32_t n, const RootTables& roots)
{
    void* raw = nullptr;
    BOOST_REQUIRE_EQUAL(
        BtxGpuFp3LdeBegin(
            n, roots.forward.empty() ? nullptr : roots.forward.data(),
            static_cast<uint32_t>(roots.forward.size()),
            roots.inverse.empty() ? nullptr : roots.inverse.data(),
            static_cast<uint32_t>(roots.inverse.size()), roots.inverse_n,
            &raw),
        0);
    BOOST_REQUIRE(raw != nullptr);
    return Context(raw);
}

void BitReverse(std::vector<gf::Fp3>& values)
{
    const size_t n = values.size();
    size_t j = 0;
    for (size_t i = 1; i < n; ++i) {
        size_t bit = n >> 1;
        for (; (j & bit) != 0; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(values[i], values[j]);
    }
}

std::vector<gf::Fp3> CpuNtt(std::vector<gf::Fp3> values,
                            const std::vector<uint64_t>& roots,
                            bool inverse, uint64_t inverse_n)
{
    for (gf::Fp3& value : values) {
        value.c0 = gf::Canonical(value.c0);
        value.c1 = gf::Canonical(value.c1);
        value.c2 = gf::Canonical(value.c2);
    }
    if (values.size() == 1) return values;
    BitReverse(values);
    const size_t n = values.size();
    for (size_t len = 2; len <= n; len <<= 1) {
        const size_t half = len / 2;
        const size_t stride = n / len;
        for (size_t base = 0; base < n; base += len) {
            for (size_t j = 0; j < half; ++j) {
                const gf::Fp3 u = values[base + j];
                const gf::Fp3 v = gf::MulBase(
                    values[base + j + half], roots[j * stride]);
                values[base + j] = gf::Add(u, v);
                values[base + j + half] = gf::Sub(u, v);
            }
        }
    }
    if (inverse) {
        for (gf::Fp3& value : values) {
            value = gf::MulBase(value, inverse_n);
        }
    }
    return values;
}

std::vector<uint64_t> Pack(const std::vector<gf::Fp3>& values)
{
    std::vector<uint64_t> out(values.size() * 3);
    for (size_t i = 0; i < values.size(); ++i) {
        out[3 * i] = values[i].c0;
        out[3 * i + 1] = values[i].c1;
        out[3 * i + 2] = values[i].c2;
    }
    return out;
}

std::vector<gf::Fp3> Unpack(const std::vector<uint64_t>& values)
{
    BOOST_REQUIRE_EQUAL(values.size() % 3, 0U);
    std::vector<gf::Fp3> out(values.size() / 3);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] =
            gf::Fp3{values[3 * i], values[3 * i + 1], values[3 * i + 2]};
    }
    return out;
}

uint64_t StructuredRawLimb(uint32_t row, uint32_t limb)
{
    static constexpr std::array<uint64_t, 8> edges{
        0, 1, gf::kP - 1, gf::kP, gf::kP + 1,
        UINT64_C(0xFFFFFFFFFFFFFFFF),
        UINT64_C(0xFFFFFFFF00000000),
        UINT64_C(0x00000000FFFFFFFF)};
    if (row < edges.size()) {
        return edges[(row + 3 * limb) % edges.size()];
    }
    const uint64_t mixed =
        (uint64_t{row + 1} * UINT64_C(0x9E3779B97F4A7C15)) ^
        (uint64_t{limb + 11} * UINT64_C(0xD6E8FEB86659FD93));
    // Exercise the unique noncanonical x+p range representable in uint64_t.
    const uint64_t small = mixed & UINT64_C(0xFFFFFFFF);
    return ((row + limb) & 3u) == 0 ? gf::kP + small : mixed;
}

std::vector<gf::Fp3> StructuredRawValues(uint32_t n)
{
    std::vector<gf::Fp3> values(n);
    for (uint32_t row = 0; row < n; ++row) {
        values[row] = gf::Fp3{
            StructuredRawLimb(row, 0),
            StructuredRawLimb(row, 1),
            StructuredRawLimb(row, 2)};
    }
    return values;
}

void RequireEqualCanonical(const std::vector<gf::Fp3>& expected,
                           const std::vector<uint64_t>& actual_aos)
{
    const std::vector<gf::Fp3> actual = Unpack(actual_aos);
    BOOST_REQUIRE_EQUAL(actual.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_TEST(actual[i].c0 < gf::kP);
        BOOST_TEST(actual[i].c1 < gf::kP);
        BOOST_TEST(actual[i].c2 < gf::kP);
        BOOST_TEST(gf::Eq(actual[i], expected[i]), "index=" << i);
    }
}

gf::Fp3 EvaluateAt(const std::vector<gf::Fp3>& coefficients,
                   gf::Fp point)
{
    gf::Fp3 sum = gf::Fp3::Zero();
    gf::Fp power = 1;
    for (const gf::Fp3& coefficient : coefficients) {
        sum = gf::Add(sum, gf::MulBase(coefficient, power));
        power = gf::Mul(power, point);
    }
    return sum;
}

} // namespace

BOOST_AUTO_TEST_CASE(forward_lde_matches_cpu_on_raw_limb_edges)
{
    if (BtxGpuFp3LdeAvailable() == 0) {
        BOOST_TEST_MESSAGE("No GPU Fp3 LDE provider; parity test skipped");
        return;
    }
    for (const uint32_t n : {1U, 2U, 4U, 8U, 32U, 256U}) {
        const RootTables roots = MakeRootTables(n);
        RootTables uploaded_roots = roots;
        if (!uploaded_roots.forward.empty()) {
            // 1 and 1+p are the same field element.  Uploading the latter at
            // root-power index zero makes root canonicalization load-bearing.
            uploaded_roots.forward[0] = gf::kP + 1;
            uploaded_roots.inverse[0] = gf::kP + 1;
        } else {
            uploaded_roots.inverse_n = gf::kP + 1;
        }
        Context context = MakeContext(n, uploaded_roots);
        const std::vector<gf::Fp3> raw = StructuredRawValues(n);
        const std::vector<gf::Fp3> expected =
            CpuNtt(raw, roots.forward, /*inverse=*/false, roots.inverse_n);
        const std::vector<uint64_t> packed = Pack(raw);
        std::vector<uint64_t> actual(static_cast<size_t>(n) * 3);
        BOOST_REQUIRE_EQUAL(
            BtxGpuFp3LdeForward(
                context.get(), packed.data(), n, actual.data()),
            0);
        RequireEqualCanonical(expected, actual);

        const std::vector<gf::Fp3> inverse_expected =
            CpuNtt(raw, roots.inverse, /*inverse=*/true, roots.inverse_n);
        BOOST_REQUIRE_EQUAL(
            BtxGpuFp3LdeInverse(
                context.get(), packed.data(), actual.data()),
            0);
        RequireEqualCanonical(inverse_expected, actual);
    }
}

BOOST_AUTO_TEST_CASE(forward_lde_is_natural_subgroup_evaluation_order)
{
    if (BtxGpuFp3LdeAvailable() == 0) return;
    constexpr uint32_t n = 16;
    const RootTables roots = MakeRootTables(n);
    Context context = MakeContext(n, roots);
    const std::vector<gf::Fp3> coefficients{
        {1, 2, 3},
        {gf::kP, gf::kP + 1, UINT64_MAX},
        {7, 11, 13},
        {17, 19, 23},
        {29, 31, 37}};
    const std::vector<uint64_t> packed = Pack(coefficients);
    std::vector<uint64_t> actual(static_cast<size_t>(n) * 3);
    BOOST_REQUIRE_EQUAL(
        BtxGpuFp3LdeForward(
            context.get(), packed.data(), coefficients.size(), actual.data()),
        0);

    std::vector<gf::Fp3> expected(n);
    gf::Fp point = 1;
    const gf::Fp omega = OmegaForSize(n);
    for (uint32_t i = 0; i < n; ++i) {
        expected[i] = EvaluateAt(coefficients, point);
        point = gf::Mul(point, omega);
    }
    RequireEqualCanonical(expected, actual);
}

BOOST_AUTO_TEST_CASE(forward_inverse_roundtrip_reuses_context_without_state)
{
    if (BtxGpuFp3LdeAvailable() == 0) return;
    constexpr uint32_t n = 1024;
    const RootTables roots = MakeRootTables(n);
    Context context = MakeContext(n, roots);
    const std::vector<gf::Fp3> raw = StructuredRawValues(n);
    const std::vector<uint64_t> packed = Pack(raw);
    std::vector<uint64_t> evaluations(static_cast<size_t>(n) * 3);
    std::vector<uint64_t> roundtrip(static_cast<size_t>(n) * 3);
    BOOST_REQUIRE_EQUAL(
        BtxGpuFp3LdeForward(
            context.get(), packed.data(), n, evaluations.data()),
        0);
    BOOST_REQUIRE_EQUAL(
        BtxGpuFp3LdeInverse(
            context.get(), evaluations.data(), roundtrip.data()),
        0);

    std::vector<gf::Fp3> canonical = raw;
    for (gf::Fp3& value : canonical) {
        value.c0 = gf::Canonical(value.c0);
        value.c1 = gf::Canonical(value.c1);
        value.c2 = gf::Canonical(value.c2);
    }
    RequireEqualCanonical(canonical, roundtrip);

    // A shorter second polynomial must not retain high coefficients from the
    // first operation in the reusable work buffer.
    const std::vector<gf::Fp3> short_polynomial{{41, 43, 47}, {53, 59, 61}};
    const std::vector<uint64_t> short_packed = Pack(short_polynomial);
    BOOST_REQUIRE_EQUAL(
        BtxGpuFp3LdeForward(
            context.get(), short_packed.data(), short_polynomial.size(),
            evaluations.data()),
        0);
    std::vector<gf::Fp3> padded(n, gf::Fp3::Zero());
    std::copy(short_polynomial.begin(), short_polynomial.end(), padded.begin());
    RequireEqualCanonical(
        CpuNtt(padded, roots.forward, false, roots.inverse_n), evaluations);
}

BOOST_AUTO_TEST_CASE(provider_rejects_malformed_shape_and_count)
{
    if (BtxGpuFp3LdeAvailable() == 0) return;
    const RootTables roots = MakeRootTables(8);
    void* malformed = nullptr;
    BOOST_TEST(BtxGpuFp3LdeBegin(
                   7, roots.forward.data(),
                   static_cast<uint32_t>(roots.forward.size()),
                   roots.inverse.data(),
                   static_cast<uint32_t>(roots.inverse.size()),
                   roots.inverse_n, &malformed) != 0);
    BOOST_TEST(malformed == nullptr);
    BOOST_TEST(BtxGpuFp3LdeBegin(
                   8, roots.forward.data(),
                   static_cast<uint32_t>(roots.forward.size() - 1),
                   roots.inverse.data(),
                   static_cast<uint32_t>(roots.inverse.size()),
                   roots.inverse_n, &malformed) != 0);
    BOOST_TEST(malformed == nullptr);

    Context context = MakeContext(8, roots);
    const std::vector<gf::Fp3> values = StructuredRawValues(9);
    const std::vector<uint64_t> packed = Pack(values);
    std::vector<uint64_t> output(8 * 3);
    BOOST_TEST(BtxGpuFp3LdeForward(
                   context.get(), packed.data(), 9, output.data()) != 0);
    BOOST_TEST(BtxGpuFp3LdeForward(
                   context.get(), nullptr, 1, output.data()) != 0);
    BOOST_TEST(BtxGpuFp3LdeInverse(
                   context.get(), nullptr, output.data()) != 0);
}

BOOST_AUTO_TEST_CASE(gpu_provider_available_when_cuda_or_metal_linked)
{
    if (BtxGpuFp3LdeAvailable() == 0) {
        BOOST_TEST_MESSAGE("GPU Fp3 LDE provider not linked; Available==0");
        return;
    }
    BOOST_TEST(BtxGpuFp3LdeAvailable() == 1);
    const RootTables roots = MakeRootTables(8);
    Context context = MakeContext(8, roots);
    const std::vector<gf::Fp3> coefficients{{1, 0, 0}, {2, 0, 0}};
    const std::vector<uint64_t> packed = Pack(coefficients);
    std::vector<uint64_t> actual(24);
    BOOST_REQUIRE_EQUAL(
        BtxGpuFp3LdeForward(
            context.get(), packed.data(),
            static_cast<uint32_t>(coefficients.size()), actual.data()),
        0);
}

BOOST_AUTO_TEST_SUITE_END()
