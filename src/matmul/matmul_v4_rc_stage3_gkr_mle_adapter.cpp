// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gkr_mle_adapter.h>

#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <utility>

namespace matmul::v4::rc::stage3_gkr_mle_adapter {

namespace safe = safe_v12;
namespace aht = alg_hash_typed;

namespace {

constexpr char CLAIM_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_MLE_CLAIMS_V1";
constexpr char MU_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_MLE_DUAL_MU_V1";
constexpr char FRI_SEED_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_MLE_MULTIROW_FRI_SEED_V1";
constexpr gf::Fp kOmega2_32 =
    UINT64_C(0x185629dcda58878c);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:gkr_mle_adapter:" + detail;
    }
    return false;
}

bool Fp3Canonical(const gf::Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool DigestCanonical(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp lane) { return lane < gf::kP; });
}

bool DigestZero(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp lane) { return lane == 0; });
}

bool DigestEq(
    const ah::Digest& left,
    const ah::Digest& right)
{
    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        if (left[lane] != right[lane]) return false;
    }
    return true;
}

std::vector<uint8_t> Domain(const char* text)
{
    const auto* begin =
        reinterpret_cast<const uint8_t*>(text);
    return {
        begin,
        begin + std::char_traits<char>::length(text)};
}

void AppendU32(
    std::vector<gf::Fp>& out,
    uint32_t value)
{
    out.push_back(gf::FromU64(value));
}

void AppendUint256(
    std::vector<gf::Fp>& out,
    const uint256& value)
{
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t limb = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            limb |=
                static_cast<uint32_t>(
                    value.data()[4 * word + byte])
                << (8 * byte);
        }
        AppendU32(out, limb);
    }
}

void AppendDigest(
    std::vector<gf::Fp>& out,
    const ah::Digest& digest)
{
    out.insert(out.end(), digest.begin(), digest.end());
}

void AppendFp3(
    std::vector<gf::Fp>& out,
    const gf::Fp3& value)
{
    out.push_back(value.c0);
    out.push_back(value.c1);
    out.push_back(value.c2);
}

ah::Digest SafeHash(
    aht::RoleV12 role,
    const char* domain,
    const std::vector<gf::Fp>& message)
{
    ah::Digest out{};
    if (!safe::SafeCoreDigestV12(
            role, Domain(domain), message, out)) {
        return {};
    }
    return out;
}

uint256 DigestToSeed(const ah::Digest& digest)
{
    uint256 out;
    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        const uint64_t value = digest[lane];
        for (uint32_t byte = 0; byte < 8; ++byte) {
            out.data()[8 * lane + byte] =
                static_cast<unsigned char>(
                    value >> (8 * byte));
        }
    }
    return out;
}

uint32_t Log2Exact(uint32_t value)
{
    uint32_t log = 0;
    while ((uint32_t{1} << log) < value) ++log;
    return log;
}

bool Fp3Less(const gf::Fp3& left, const gf::Fp3& right)
{
    if (left.c0 != right.c0) return left.c0 < right.c0;
    if (left.c1 != right.c1) return left.c1 < right.c1;
    return left.c2 < right.c2;
}

bool SamePoint(
    const std::vector<gf::Fp3>& left,
    const std::vector<gf::Fp3>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (!gf::Eq(left[i], right[i])) return false;
    }
    return true;
}

bool ClaimTargetLess(
    const OpeningClaimV1& left,
    const OpeningClaimV1& right)
{
    if (left.global_column_id !=
        right.global_column_id) {
        return left.global_column_id <
            right.global_column_id;
    }
    return std::lexicographical_compare(
        left.point.begin(), left.point.end(),
        right.point.begin(), right.point.end(),
        Fp3Less);
}

bool ValidateClaims(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims,
    std::string* why)
{
    if (claims.empty() ||
        claims.size() > kMaxClaimsV1 ||
        receipt.range.column_count == 0 ||
        receipt.fri_proof.n_coeffs < 2 ||
        (receipt.fri_proof.n_coeffs &
         (receipt.fri_proof.n_coeffs - 1U)) != 0) {
        return Fail(why, "claim_shape");
    }
    const uint32_t dimension =
        Log2Exact(receipt.fri_proof.n_coeffs);
    const uint64_t range_end =
        static_cast<uint64_t>(
            receipt.range.first_column) +
        receipt.range.column_count;
    for (size_t index = 0;
         index < claims.size(); ++index) {
        const auto& claim = claims[index];
        if (claim.global_column_id <
                receipt.range.first_column ||
            claim.global_column_id >= range_end ||
            claim.global_column_id >=
                descriptor.columns.size() ||
            claim.point.size() != dimension ||
            !Fp3Canonical(claim.value) ||
            std::any_of(
                claim.point.begin(), claim.point.end(),
                [](const gf::Fp3& value) {
                    return !Fp3Canonical(value);
                })) {
            return Fail(why, "claim_target_or_field");
        }
        if (index > 0 &&
            (!ClaimTargetLess(
                 claims[index - 1], claim) ||
             (claims[index - 1].global_column_id ==
                  claim.global_column_id &&
              SamePoint(
                  claims[index - 1].point,
                  claim.point)))) {
            return Fail(why, "claim_order_or_duplicate");
        }
    }
    return true;
}

std::vector<gf::Fp> ClaimMessage(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims)
{
    std::vector<gf::Fp> message;
    message.reserve(
        64 + claims.size() *
            (6 + 3 * claims.front().point.size()));
    AppendU32(message, kProofVersionV1);
    AppendDigest(message, descriptor.descriptor_root);
    AppendDigest(message, receipt.receipt_root);
    AppendDigest(message, receipt.proof_statement_root);
    AppendDigest(message, receipt.evaluation_root);
    AppendDigest(
        message, receipt.fri_proof.row_commit.root);
    AppendUint256(message, receipt.chunk_fs_seed);
    AppendU32(message, receipt.range.first_column);
    AppendU32(message, receipt.range.column_count);
    AppendU32(message, receipt.fri_proof.n_coeffs);
    AppendU32(
        message,
        static_cast<uint32_t>(claims.size()));
    for (const auto& claim : claims) {
        AppendU32(message, claim.global_column_id);
        AppendU32(
            message,
            static_cast<uint32_t>(claim.point.size()));
        for (const auto& coordinate : claim.point) {
            AppendFp3(message, coordinate);
        }
        AppendFp3(message, claim.value);
    }
    return message;
}

bool DeriveMu(
    const ah::Digest& claim_root,
    uint32_t family,
    uint32_t index,
    gf::Fp3& out,
    std::string* why)
{
    if (!DigestCanonical(claim_root) ||
        DigestZero(claim_root) ||
        family >= 2) {
        return Fail(why, "mu_input");
    }
    std::vector<gf::Fp> message;
    AppendU32(message, kProofVersionV1);
    AppendDigest(message, claim_root);
    AppendU32(message, family);
    AppendU32(message, index);
    const ah::Digest digest =
        SafeHash(
            aht::RoleV12::TranscriptBatchCoefficient,
            MU_DOMAIN_V1, message);
    if (DigestZero(digest) ||
        !DigestCanonical(digest)) {
        return Fail(why, "mu_safe_core");
    }
    out = {
        digest[0], digest[1], digest[2]};
    return true;
}

bool DeriveAllMu(
    const ah::Digest& claim_root,
    uint32_t count,
    std::array<std::vector<gf::Fp3>, 2>& mu,
    std::string* why)
{
    for (uint32_t family = 0;
         family < mu.size(); ++family) {
        mu[family].resize(count);
        for (uint32_t index = 0;
             index < count; ++index) {
            if (!DeriveMu(
                    claim_root, family, index,
                    mu[family][index], why)) {
                return false;
            }
        }
    }
    return true;
}

gf::Fp PowFp(gf::Fp base, uint64_t exponent)
{
    gf::Fp result = 1;
    while (exponent > 0) {
        if ((exponent & 1U) != 0) {
            result = gf::Mul(result, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return result;
}

gf::Fp OmegaForSize(uint32_t size)
{
    return PowFp(
        kOmega2_32,
        uint64_t{1} <<
            (32U - Log2Exact(size)));
}

void BitReverse(std::vector<gf::Fp3>& values)
{
    const size_t size = values.size();
    size_t reverse = 0;
    for (size_t index = 1;
         index < size; ++index) {
        size_t bit = size >> 1;
        while ((reverse & bit) != 0) {
            reverse ^= bit;
            bit >>= 1;
        }
        reverse ^= bit;
        if (index < reverse) {
            std::swap(values[index], values[reverse]);
        }
    }
}

void Ntt(std::vector<gf::Fp3>& values, bool inverse)
{
    const size_t size = values.size();
    if (size <= 1) return;
    BitReverse(values);
    gf::Fp omega =
        OmegaForSize(static_cast<uint32_t>(size));
    if (inverse) omega = gf::Inv(omega);
    for (size_t length = 2;; length <<= 1) {
        const gf::Fp step =
            PowFp(omega, size / length);
        for (size_t first = 0;
             first < size; first += length) {
            gf::Fp twiddle = 1;
            for (size_t offset = 0;
                 offset < length / 2; ++offset) {
                const gf::Fp3 even =
                    values[first + offset];
                const gf::Fp3 odd =
                    gf::MulBase(
                        values[
                            first + offset +
                            length / 2],
                        twiddle);
                values[first + offset] =
                    gf::Add(even, odd);
                values[
                    first + offset + length / 2] =
                    gf::Sub(even, odd);
                twiddle = gf::Mul(twiddle, step);
            }
        }
        if (length == size) break;
    }
    if (inverse) {
        const gf::Fp inv_size =
            gf::Inv(static_cast<gf::Fp>(size));
        for (auto& value : values) {
            value = gf::MulBase(value, inv_size);
        }
    }
}

struct WitnessColumns {
    std::array<gf::Fp3, 2> sigma{};
    std::array<std::vector<gf::Fp3>, 2> f;
    std::array<std::vector<gf::Fp3>, 2> g;
};

void SplitLemmaWitness(
    const std::vector<gf::Fp3>& convolution,
    uint32_t n,
    std::vector<gf::Fp3>& f,
    std::vector<gf::Fp3>& g)
{
    f.assign(n - 1U, gf::Fp3::Zero());
    g.assign(n, gf::Fp3::Zero());
    for (uint32_t index = 0;
         index + 1U < n; ++index) {
        f[index] = gf::Add(
            convolution[index],
            convolution[index + n]);
    }
    for (uint32_t index = 0;
         index < n; ++index) {
        g[index] =
            convolution[index + n - 1U];
    }
}

bool BuildDirectWitnessColumns(
    const wireless::ReceiptV1& receipt,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const std::vector<OpeningClaimV1>& claims,
    const std::array<std::vector<gf::Fp3>, 2>& mu,
    WitnessColumns& out,
    std::string* why)
{
    const uint32_t n = receipt.fri_proof.n_coeffs;
    if (n < 2) return Fail(why, "direct_witness_domain");
    std::array<std::vector<gf::Fp3>, 2>
        convolution{
            std::vector<gf::Fp3>(
                2U * n, gf::Fp3::Zero()),
            std::vector<gf::Fp3>(
                2U * n, gf::Fp3::Zero())};
    for (uint32_t family = 0;
         family < 2; ++family) {
        out.sigma[family] = gf::Fp3::Zero();
        for (uint32_t claim = 0;
             claim < claims.size(); ++claim) {
            out.sigma[family] = gf::Add(
                out.sigma[family],
                gf::Mul(
                    mu[family][claim],
                    claims[claim].value));
        }
    }
    for (uint32_t claim = 0;
         claim < claims.size(); ++claim) {
        const uint32_t local =
            claims[claim].global_column_id -
            receipt.range.first_column;
        if (local >= columns.size()) {
            return Fail(why, "direct_claim_column");
        }
        const auto kernel =
            RCGkrEqKernelCoeffs3(
                claims[claim].point);
        if (kernel.size() != n) {
            return Fail(why, "direct_kernel");
        }
        for (uint32_t p_index = 0;
             p_index < columns[local].size();
             ++p_index) {
            for (uint32_t q_index = 0;
                 q_index < n; ++q_index) {
                const gf::Fp3 product =
                    gf::Mul(
                        columns[local][p_index],
                        kernel[n - 1U - q_index]);
                for (uint32_t family = 0;
                     family < 2; ++family) {
                    convolution[family][
                        p_index + q_index] =
                        gf::Add(
                            convolution[family][
                                p_index + q_index],
                            gf::Mul(
                                mu[family][claim],
                                product));
                }
            }
        }
    }
    for (uint32_t family = 0;
         family < 2; ++family) {
        SplitLemmaWitness(
            convolution[family], n,
            out.f[family], out.g[family]);
    }
    return true;
}

bool BuildWitnessColumns(
    const wireless::ReceiptV1& receipt,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const std::vector<OpeningClaimV1>& claims,
    const std::array<std::vector<gf::Fp3>, 2>& mu,
    WitnessColumns& out,
    std::string* why)
{
    const uint32_t n = receipt.fri_proof.n_coeffs;
    if (n < 2 || n > (uint32_t{1} << 30)) {
        return Fail(why, "witness_domain");
    }
    for (uint32_t family = 0;
         family < 2; ++family) {
        out.sigma[family] = gf::Fp3::Zero();
        for (uint32_t claim = 0;
             claim < claims.size(); ++claim) {
            out.sigma[family] = gf::Add(
                out.sigma[family],
                gf::Mul(
                    mu[family][claim],
                    claims[claim].value));
        }
    }

    // Tiny domains use the direct construction to make the algebra auditable.
    // Larger domains use a 2N Goldilocks NTT convolution; the old O(N^2)
    // EvalArgumentProve3 loop is not viable for production-shaped columns.
    if (n <= 64) {
        return BuildDirectWitnessColumns(
            receipt, columns, claims, mu,
            out, why);
    }

    const uint64_t transform_size64 =
        2ULL * n;
    if (transform_size64 >
            (uint64_t{1} << 32) ||
        transform_size64 >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "witness_ntt_domain");
    }
    const uint32_t transform_size =
        static_cast<uint32_t>(transform_size64);
    std::array<std::vector<gf::Fp3>, 2>
        frequency{
            std::vector<gf::Fp3>(
                transform_size, gf::Fp3::Zero()),
            std::vector<gf::Fp3>(
                transform_size, gf::Fp3::Zero())};
    for (uint32_t claim = 0;
         claim < claims.size(); ++claim) {
        const uint32_t local =
            claims[claim].global_column_id -
            receipt.range.first_column;
        std::vector<gf::Fp3> polynomial(
            transform_size, gf::Fp3::Zero());
        std::copy(
            columns[local].begin(),
            columns[local].end(),
            polynomial.begin());
        Ntt(polynomial, false);

        std::vector<gf::Fp3> kernel =
            RCGkrEqKernelCoeffs3(
                claims[claim].point);
        std::reverse(kernel.begin(), kernel.end());
        kernel.resize(
            transform_size, gf::Fp3::Zero());
        Ntt(kernel, false);
        for (uint32_t index = 0;
             index < transform_size; ++index) {
            const gf::Fp3 product =
                gf::Mul(
                    polynomial[index], kernel[index]);
            for (uint32_t family = 0;
                 family < 2; ++family) {
                frequency[family][index] =
                    gf::Add(
                        frequency[family][index],
                        gf::Mul(
                            mu[family][claim],
                            product));
            }
        }
    }
    for (uint32_t family = 0;
         family < 2; ++family) {
        Ntt(frequency[family], true);
        SplitLemmaWitness(
            frequency[family], n,
            out.f[family], out.g[family]);
    }
    return true;
}

gf::Fp3 PowFp3(gf::Fp3 base, uint64_t exponent)
{
    gf::Fp3 result = gf::Fp3::One();
    while (exponent > 0) {
        if ((exponent & 1U) != 0) {
            result = gf::Mul(result, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return result;
}

gf::Fp3 QStarAt(
    const std::vector<gf::Fp3>& point,
    const gf::Fp3& z,
    uint32_t n)
{
    return gf::Mul(
        PowFp3(z, n - 1U),
        RCGkrEqKernelAt3(point, gf::Inv(z)));
}

uint256 DeriveFriSeed(
    const wireless::ReceiptV1& receipt,
    const ah::Digest& claim_root,
    const ah::Digest& auxiliary_root,
    const ah::Digest& quotient_root)
{
    std::vector<gf::Fp> message;
    AppendU32(message, kProofVersionV1);
    AppendDigest(message, receipt.descriptor_root);
    AppendDigest(message, receipt.receipt_root);
    AppendDigest(message, claim_root);
    AppendDigest(
        message, receipt.fri_proof.row_commit.root);
    AppendDigest(message, auxiliary_root);
    AppendDigest(message, quotient_root);
    AppendU32(message, receipt.range.first_column);
    AppendU32(message, receipt.range.column_count);
    AppendU32(message, receipt.fri_proof.n_coeffs);
    const ah::Digest digest =
        SafeHash(
            aht::RoleV12::TranscriptFriSeed,
            FRI_SEED_DOMAIN_V1, message);
    return DigestToSeed(digest);
}

bool VerifyBatchShape(
    const wireless::ReceiptV1& receipt,
    const ProofV1& proof,
    std::string* why)
{
    const auto& batch = proof.batch;
    const uint32_t width =
        receipt.range.column_count;
    if (batch.version !=
            kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13 ||
        batch.n_coeffs !=
            receipt.fri_proof.n_coeffs ||
        batch.groups.size() != 3 ||
        batch.column_len.size() !=
            static_cast<size_t>(width) + 4U ||
        batch.groups[0].role !=
            Fri3AlgMultiRowGroupRole::MainTrace ||
        batch.groups[0].first_column != 0 ||
        batch.groups[0].column_count != width ||
        batch.groups[1].role !=
            Fri3AlgMultiRowGroupRole::AuxiliaryTrace ||
        batch.groups[1].first_column != width ||
        batch.groups[1].column_count != 2 ||
        batch.groups[2].role !=
            Fri3AlgMultiRowGroupRole::Quotient ||
        batch.groups[2].first_column != width + 2U ||
        batch.groups[2].column_count != 2 ||
        !DigestEq(
            batch.groups[0].row_commit.root,
            receipt.fri_proof.row_commit.root) ||
        !DigestEq(
            proof.main_row_root,
            receipt.fri_proof.row_commit.root)) {
        return Fail(why, "batch_shape_or_main_root");
    }
    for (uint32_t column = 0;
         column < width; ++column) {
        if (batch.column_len[column] !=
                receipt.fri_proof.column_len[column]) {
            return Fail(why, "batch_main_length");
        }
    }
    const uint32_t n = batch.n_coeffs;
    if (batch.column_len[width] != n - 1U ||
        batch.column_len[width + 1U] != n ||
        batch.column_len[width + 2U] != n - 1U ||
        batch.column_len[width + 3U] != n ||
        proof.evaluation_argument.f_column !=
            std::array<uint32_t, 2>{
                width, width + 2U} ||
        proof.evaluation_argument.g_column !=
            std::array<uint32_t, 2>{
                width + 1U, width + 3U}) {
        return Fail(why, "batch_witness_shape");
    }
    return true;
}

bool VerifyDualIdentities(
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims,
    const ProofV1& proof,
    const std::array<std::vector<gf::Fp3>, 2>& mu,
    std::string* why)
{
    const auto& batch = proof.batch;
    const uint32_t n = batch.n_coeffs;
    std::array<gf::Fp3, 2> sigma{
        gf::Fp3::Zero(), gf::Fp3::Zero()};
    for (uint32_t family = 0;
         family < 2; ++family) {
        for (uint32_t claim = 0;
             claim < claims.size(); ++claim) {
            sigma[family] = gf::Add(
                sigma[family],
                gf::Mul(
                    mu[family][claim],
                    claims[claim].value));
        }
        if (!gf::Eq(
                sigma[family],
                proof.evaluation_argument
                    .sigma[family])) {
            return Fail(
                why,
                family == 0
                    ? "sigma0_mismatch"
                    : "sigma1_mismatch");
        }
    }

    for (uint32_t sample = 0;
         sample < 2; ++sample) {
        const gf::Fp3& z =
            sample == 0 ? batch.z1 : batch.z2;
        const auto& evaluations =
            sample == 0
            ? batch.evals_z1
            : batch.evals_z2;
        for (uint32_t family = 0;
             family < 2; ++family) {
            gf::Fp3 lhs = gf::Fp3::Zero();
            for (uint32_t claim = 0;
                 claim < claims.size(); ++claim) {
                const uint32_t local =
                    claims[claim].global_column_id -
                    receipt.range.first_column;
                lhs = gf::Add(
                    lhs,
                    gf::Mul(
                        gf::Mul(
                            mu[family][claim],
                            evaluations[local]),
                        QStarAt(
                            claims[claim].point,
                            z, n)));
            }
            lhs = gf::Mul(z, lhs);
            const uint32_t f_column =
                proof.evaluation_argument
                    .f_column[family];
            const uint32_t g_column =
                proof.evaluation_argument
                    .g_column[family];
            gf::Fp3 rhs = gf::Mul(
                evaluations[g_column],
                gf::Sub(
                    PowFp3(z, n),
                    gf::Fp3::One()));
            rhs = gf::Add(
                rhs,
                gf::Mul(
                    z, evaluations[f_column]));
            rhs = gf::Add(rhs, sigma[family]);
            if (!gf::Eq(lhs, rhs)) {
                return Fail(
                    why,
                    "evaluation_identity_" +
                    std::to_string(family) + "_" +
                    std::to_string(sample));
            }
        }
    }
    return true;
}

void AppendByteU16(
    std::vector<unsigned char>& out,
    uint16_t value)
{
    out.push_back(
        static_cast<unsigned char>(value));
    out.push_back(
        static_cast<unsigned char>(value >> 8));
}

void AppendByteU32(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

void AppendByteU64(
    std::vector<unsigned char>& out,
    uint64_t value)
{
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

void AppendByteDigest(
    std::vector<unsigned char>& out,
    const ah::Digest& digest)
{
    for (const gf::Fp lane : digest) {
        AppendByteU64(out, lane);
    }
}

void AppendByteFp3(
    std::vector<unsigned char>& out,
    const gf::Fp3& value)
{
    AppendByteU64(out, value.c0);
    AppendByteU64(out, value.c1);
    AppendByteU64(out, value.c2);
}

bool ReadU16(
    const std::vector<unsigned char>& bytes,
    size_t& offset, uint16_t& out)
{
    if (bytes.size() - offset < 2) return false;
    out =
        static_cast<uint16_t>(bytes[offset]) |
        static_cast<uint16_t>(bytes[offset + 1])
            << 8;
    offset += 2;
    return true;
}

bool ReadU32(
    const std::vector<unsigned char>& bytes,
    size_t& offset, uint32_t& out)
{
    if (bytes.size() - offset < 4) return false;
    out = 0;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out |= static_cast<uint32_t>(
            bytes[offset + byte]) << (8 * byte);
    }
    offset += 4;
    return true;
}

bool ReadU64(
    const std::vector<unsigned char>& bytes,
    size_t& offset, uint64_t& out)
{
    if (bytes.size() - offset < 8) return false;
    out = 0;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out |= static_cast<uint64_t>(
            bytes[offset + byte]) << (8 * byte);
    }
    offset += 8;
    return true;
}

bool ReadDigest(
    const std::vector<unsigned char>& bytes,
    size_t& offset, ah::Digest& out)
{
    for (gf::Fp& lane : out) {
        if (!ReadU64(bytes, offset, lane) ||
            lane >= gf::kP) {
            return false;
        }
    }
    return true;
}

bool ReadFp3(
    const std::vector<unsigned char>& bytes,
    size_t& offset, gf::Fp3& out)
{
    return ReadU64(bytes, offset, out.c0) &&
        ReadU64(bytes, offset, out.c1) &&
        ReadU64(bytes, offset, out.c2) &&
        Fp3Canonical(out);
}

} // namespace

std::optional<size_t> EstimateProofBytesV1(
    uint32_t receipt_columns,
    uint32_t n_coeffs)
{
    if (receipt_columns == 0 ||
        receipt_columns >
            kMaxReceiptColumnsPerProofV1 ||
        n_coeffs < 2 ||
        (n_coeffs & (n_coeffs - 1U)) != 0 ||
        n_coeffs > kRCGkrColumnMaxCoeffs) {
        return std::nullopt;
    }
    uint64_t folds = 0;
    for (uint32_t value = n_coeffs;
         value > 1; value >>= 1) {
        ++folds;
    }
    const uint64_t row_depth = folds + 4U;
    const uint64_t width =
        static_cast<uint64_t>(receipt_columns) + 4U;
    constexpr uint64_t FP3_BYTES = 24U;
    constexpr uint64_t DIGEST_BYTES = 32U;
    // Exact MultiRowCodecShape fixed envelope for exactly three groups.
    const unsigned __int128 fixed =
        28U +
        3U * 48U +
        4U + 4U * static_cast<unsigned __int128>(width) +
        3U * FP3_BYTES +
        2U * (4U +
              FP3_BYTES *
                  static_cast<unsigned __int128>(width)) +
        2U * FP3_BYTES +
        4U +
        36U *
            static_cast<unsigned __int128>(folds + 1U) +
        FP3_BYTES +
        4U +
        FP3_BYTES *
            static_cast<unsigned __int128>(folds) +
        4U;
    const unsigned __int128 path_depth_sum =
        static_cast<unsigned __int128>(folds) *
            row_depth -
        static_cast<unsigned __int128>(folds) *
            (folds - 1U) / 2U;
    const unsigned __int128 query =
        36U +
        FP3_BYTES *
            static_cast<unsigned __int128>(width) +
        3U * DIGEST_BYTES * row_depth +
        64U * static_cast<unsigned __int128>(folds) +
        64U * path_depth_sum;
    // Adapter wrapper fixed prefix (magic/version/roots/sigmas/ids/length).
    constexpr uint64_t WRAPPER_BYTES =
        4U + 2U + 2U + 4U * 32U +
        2U * 24U + 4U * 4U + 4U;
    const unsigned __int128 total =
        WRAPPER_BYTES + fixed +
        kRCFri3AlgNumQueries * query;
    if (total >
        std::numeric_limits<size_t>::max()) {
        return std::nullopt;
    }
    return static_cast<size_t>(total);
}

std::vector<wireless::ChunkRangeV1>
BuildChunkPlanV1(
    const wireless::PublicDescriptorV1& descriptor,
    uint32_t max_columns_per_receipt)
{
    std::vector<wireless::ChunkRangeV1> out;
    if (!wireless::ValidatePublicDescriptorV1(
            descriptor, nullptr) ||
        max_columns_per_receipt == 0 ||
        max_columns_per_receipt >
            kMaxReceiptColumnsPerProofV1) {
        return out;
    }
    uint32_t first = 0;
    while (first < descriptor.columns.size()) {
        uint32_t count = 0;
        uint32_t n_coeffs = 1;
        while (count < max_columns_per_receipt &&
               first + count <
                   descriptor.columns.size()) {
            const uint64_t length =
                descriptor.columns[
                    first + count].logical_len;
            if (length == 0 ||
                length > kRCGkrColumnMaxCoeffs) {
                break;
            }
            while (n_coeffs < length) {
                n_coeffs <<= 1;
            }
            const uint32_t candidate = count + 1U;
            const auto receipt_bytes =
                wireless::EstimateQ192V13ProofBytesV1(
                    candidate, n_coeffs);
            const auto adapter_bytes =
                EstimateProofBytesV1(
                    candidate, n_coeffs);
            if (!receipt_bytes.has_value() ||
                !adapter_bytes.has_value() ||
                *receipt_bytes >
                    kRCFriMaxProofBytesHard ||
                *adapter_bytes > kMaxProofBytesV1) {
                break;
            }
            count = candidate;
        }
        if (count == 0) {
            out.clear();
            return out;
        }
        out.push_back({first, count});
        first += count;
    }
    return out;
}

WitnessDifferentialAuditV1
AuditNttWitnessConstructionV1()
{
    WitnessDifferentialAuditV1 out;
    out.n_coeffs = 128;
    out.claims = 3;
    wireless::ReceiptV1 receipt;
    receipt.range = {0, 2};
    receipt.fri_proof.n_coeffs = out.n_coeffs;
    std::vector<std::vector<gf::Fp3>> columns(
        2, std::vector<gf::Fp3>(out.n_coeffs));
    for (uint32_t column = 0; column < 2; ++column) {
        for (uint32_t row = 0;
             row < out.n_coeffs; ++row) {
            columns[column][row] = {
                gf::FromU64(1 + 31 * column + 3 * row),
                gf::FromU64(2 + 37 * column + 5 * row),
                gf::FromU64(3 + 41 * column + 7 * row)};
        }
    }
    auto point = [](uint32_t salt) {
        std::vector<gf::Fp3> out(7);
        for (uint32_t i = 0; i < out.size(); ++i) {
            out[i] = {
                gf::FromU64(5 + salt + 7 * i),
                gf::FromU64(11 + salt + 13 * i),
                gf::FromU64(17 + salt + 19 * i)};
        }
        return out;
    };
    std::vector<OpeningClaimV1> claims;
    claims.push_back({
        0, point(0),
        RCGkrMleEval1D3(columns[0], point(0))});
    claims.push_back({
        0, point(1),
        RCGkrMleEval1D3(columns[0], point(1))});
    claims.push_back({
        1, point(2),
        RCGkrMleEval1D3(columns[1], point(2))});
    std::vector<gf::Fp> root_message;
    AppendU32(root_message, out.n_coeffs);
    AppendU32(root_message, out.claims);
    const ah::Digest claim_root =
        SafeHash(
            aht::RoleV12::
                ApplicationStatementCommitment,
            CLAIM_DOMAIN_V1, root_message);
    std::array<std::vector<gf::Fp3>, 2> mu;
    std::string why;
    if (!DeriveAllMu(
            claim_root, out.claims, mu, &why)) {
        out.note = why;
        return out;
    }
    WitnessColumns ntt;
    WitnessColumns direct;
    if (!BuildWitnessColumns(
            receipt, columns, claims, mu,
            ntt, &why) ||
        !BuildDirectWitnessColumns(
            receipt, columns, claims, mu,
            direct, &why)) {
        out.note = why;
        return out;
    }
    out.ntt_path_executed = out.n_coeffs > 64;
    out.dual_sigma_matches = true;
    out.all_witness_coefficients_match = true;
    for (uint32_t family = 0; family < 2; ++family) {
        out.dual_sigma_matches &=
            gf::Eq(
                ntt.sigma[family],
                direct.sigma[family]);
        if (ntt.f[family].size() !=
                direct.f[family].size() ||
            ntt.g[family].size() !=
                direct.g[family].size()) {
            out.all_witness_coefficients_match = false;
            continue;
        }
        for (uint32_t i = 0;
             i < ntt.f[family].size(); ++i) {
            out.all_witness_coefficients_match &=
                gf::Eq(
                    ntt.f[family][i],
                    direct.f[family][i]);
        }
        for (uint32_t i = 0;
             i < ntt.g[family].size(); ++i) {
            out.all_witness_coefficients_match &=
                gf::Eq(
                    ntt.g[family][i],
                    direct.g[family][i]);
        }
    }
    auto eval_poly = [](
        const std::vector<gf::Fp3>& coefficients,
        const gf::Fp3& x) {
        gf::Fp3 value = gf::Fp3::Zero();
        for (auto it = coefficients.rbegin();
             it != coefficients.rend(); ++it) {
            value = gf::Add(gf::Mul(value, x), *it);
        }
        return value;
    };
    out.both_families_hold_at_both_points = true;
    const std::array<gf::Fp3, 2> z{
        gf::Fp3{
            gf::FromU64(101), gf::FromU64(7),
            gf::FromU64(13)},
        gf::Fp3{
            gf::FromU64(103), gf::FromU64(17),
            gf::FromU64(23)}};
    for (uint32_t family = 0; family < 2; ++family) {
        for (const auto& sample : z) {
            gf::Fp3 lhs = gf::Fp3::Zero();
            for (uint32_t claim = 0;
                 claim < claims.size(); ++claim) {
                lhs = gf::Add(
                    lhs,
                    gf::Mul(
                        gf::Mul(
                            mu[family][claim],
                            eval_poly(
                                columns[
                                    claims[claim]
                                        .global_column_id],
                                sample)),
                        QStarAt(
                            claims[claim].point,
                            sample, out.n_coeffs)));
            }
            lhs = gf::Mul(sample, lhs);
            gf::Fp3 rhs = gf::Mul(
                eval_poly(ntt.g[family], sample),
                gf::Sub(
                    PowFp3(sample, out.n_coeffs),
                    gf::Fp3::One()));
            rhs = gf::Add(
                rhs,
                gf::Mul(
                    sample,
                    eval_poly(ntt.f[family], sample)));
            rhs = gf::Add(rhs, ntt.sigma[family]);
            out.both_families_hold_at_both_points &=
                gf::Eq(lhs, rhs);
        }
    }
    out.valid =
        out.ntt_path_executed &&
        out.dual_sigma_matches &&
        out.all_witness_coefficients_match &&
        out.both_families_hold_at_both_points;
    out.note = out.valid
        ? "stage3:gkr_mle_adapter:"
          "n128_ntt_matches_direct"
        : "stage3:gkr_mle_adapter:"
          "n128_ntt_differential_failed";
    return out;
}

ah::Digest ComputeClaimRootV1(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims)
{
    std::string why;
    if (!wireless::ValidatePublicDescriptorV1(
            descriptor, &why) ||
        !ValidateClaims(
            descriptor, receipt, claims, &why)) {
        return {};
    }
    return SafeHash(
        aht::RoleV12::ApplicationStatementCommitment,
        CLAIM_DOMAIN_V1,
        ClaimMessage(descriptor, receipt, claims));
}

ProveResultV1 ProveV1(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<std::vector<gf::Fp3>>&
        receipt_columns,
    const std::vector<OpeningClaimV1>& claims)
{
    ProveResultV1 out;
    const auto fail =
        [&](const std::string& detail) {
            out.note =
                "stage3:gkr_mle_adapter:prove:" +
                detail;
            return out;
        };
    std::string why;
    if (!wireless::ValidatePublicDescriptorV1(
            descriptor, &why) ||
        !ValidateClaims(
            descriptor, receipt, claims, &why)) {
        return fail(why);
    }
    if (receipt_columns.size() !=
            receipt.range.column_count ||
        receipt.fri_proof.column_len.size() !=
            receipt.range.column_count) {
        return fail("column_count");
    }
    for (uint32_t local = 0;
         local < receipt_columns.size(); ++local) {
        if (receipt_columns[local].size() !=
                receipt.fri_proof.column_len[local] ||
            std::any_of(
                receipt_columns[local].begin(),
                receipt_columns[local].end(),
                [](const gf::Fp3& value) {
                    return !Fp3Canonical(value);
                })) {
            return fail("column_length_or_field");
        }
    }
    const ah::Digest claim_root =
        ComputeClaimRootV1(
            descriptor, receipt, claims);
    if (DigestZero(claim_root)) {
        return fail("claim_root");
    }
    std::array<std::vector<gf::Fp3>, 2> mu;
    if (!DeriveAllMu(
            claim_root,
            static_cast<uint32_t>(claims.size()),
            mu, &why)) {
        return fail(why);
    }

    try {
        auto main_cache =
            std::make_shared<Fri3AlgRowTreeCache>();
        if (!Fri3AlgBuildRowTreeCacheStreaming(
                receipt_columns,
                receipt.fri_proof.n_coeffs,
                *main_cache, &why) ||
            !DigestEq(
                main_cache->root,
                receipt.fri_proof.row_commit.root)) {
            return fail(
                "receipt_column_root:" + why);
        }

        WitnessColumns witnesses;
        if (!BuildWitnessColumns(
                receipt, receipt_columns,
                claims, mu, witnesses, &why)) {
            return fail(why);
        }
        const std::vector<std::vector<gf::Fp3>>
            auxiliary{
                witnesses.f[0],
                witnesses.g[0]};
        const std::vector<std::vector<gf::Fp3>>
            quotient{
                witnesses.f[1],
                witnesses.g[1]};
        auto auxiliary_cache =
            std::make_shared<Fri3AlgRowTreeCache>();
        auto quotient_cache =
            std::make_shared<Fri3AlgRowTreeCache>();
        if (!Fri3AlgBuildRowTreeCacheStreaming(
                auxiliary,
                receipt.fri_proof.n_coeffs,
                *auxiliary_cache, &why) ||
            !Fri3AlgBuildRowTreeCacheStreaming(
                quotient,
                receipt.fri_proof.n_coeffs,
                *quotient_cache, &why)) {
            return fail("witness_cache:" + why);
        }
        const uint256 fri_seed =
            DeriveFriSeed(
                receipt, claim_root,
                auxiliary_cache->root,
                quotient_cache->root);
        if (fri_seed.IsNull()) {
            return fail("fri_seed");
        }
        const std::vector<
            std::vector<std::vector<gf::Fp3>>>
            groups{
                receipt_columns,
                auxiliary,
                quotient};
        const std::vector<
            Fri3AlgMultiRowGroupRole>
            roles{
                Fri3AlgMultiRowGroupRole::MainTrace,
                Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
                Fri3AlgMultiRowGroupRole::Quotient};
        const auto committed =
            Fri3AlgMultiRowSafeQ192K2V13BatchCommitStreaming(
                groups, roles, fri_seed, 0,
                {main_cache, auxiliary_cache,
                 quotient_cache});
        if (!committed.ok) {
            return fail(committed.note);
        }

        out.proof.version = kProofVersionV1;
        out.proof.descriptor_root =
            descriptor.descriptor_root;
        out.proof.receipt_root =
            receipt.receipt_root;
        out.proof.claim_root = claim_root;
        out.proof.main_row_root =
            main_cache->root;
        out.proof.evaluation_argument.sigma =
            witnesses.sigma;
        const uint32_t width =
            receipt.range.column_count;
        out.proof.evaluation_argument.f_column =
            {width, width + 2U};
        out.proof.evaluation_argument.g_column =
            {width + 1U, width + 3U};
        out.proof.batch = committed.proof;
        std::vector<unsigned char> encoded;
        out.proof_bytes =
            SerializeProofV1(out.proof, encoded);
        if (out.proof_bytes == 0 ||
            out.proof_bytes != encoded.size() ||
            out.proof_bytes > kMaxProofBytesV1) {
            return fail("wire_cap");
        }
        out.audit =
            VerifyV1(
                descriptor, receipt,
                claims, out.proof);
        if (!out.audit.valid) {
            return fail(out.audit.note);
        }
        out.ok = true;
        out.note =
            "stage3:gkr_mle_adapter:prove:"
            "receipt_R0_then_dual_SAFE_mu_then_"
            "two_quotient_roots_then_V13";
        return out;
    } catch (const std::bad_alloc&) {
        return fail("memory_exhausted");
    }
}

AuditV1 VerifyV1(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ReceiptV1& receipt,
    const std::vector<OpeningClaimV1>& claims,
    const ProofV1& proof)
{
    AuditV1 out;
    std::string why;
    if (!wireless::ValidatePublicDescriptorV1(
            descriptor, &why) ||
        proof.version != kProofVersionV1 ||
        !DigestCanonical(proof.descriptor_root) ||
        !DigestCanonical(proof.receipt_root) ||
        !DigestCanonical(proof.claim_root) ||
        !DigestCanonical(proof.main_row_root) ||
        !DigestEq(
            proof.descriptor_root,
            descriptor.descriptor_root) ||
        !DigestEq(
            proof.receipt_root,
            receipt.receipt_root)) {
        out.note =
            "stage3:gkr_mle_adapter:"
            "public_binding";
        return out;
    }
    out.canonical_claims =
        ValidateClaims(
            descriptor, receipt, claims, &why);
    if (!out.canonical_claims) {
        out.note = why;
        return out;
    }
    const ah::Digest expected_claim_root =
        ComputeClaimRootV1(
            descriptor, receipt, claims);
    out.claim_transcript_bound =
        !DigestZero(expected_claim_root) &&
        DigestEq(
            expected_claim_root,
            proof.claim_root);
    if (!out.claim_transcript_bound) {
        out.note =
            "stage3:gkr_mle_adapter:"
            "claim_transplant";
        return out;
    }
    const auto receipt_audit =
        wireless::VerifyReceiptV1(
            descriptor, receipt);
    out.receipt_verified = receipt_audit.valid;
    if (!out.receipt_verified) {
        out.note =
            "stage3:gkr_mle_adapter:receipt:" +
            receipt_audit.note;
        return out;
    }
    out.receipt_row_root_reused =
        VerifyBatchShape(
            receipt, proof, &why);
    if (!out.receipt_row_root_reused) {
        out.note = why;
        return out;
    }

    std::array<std::vector<gf::Fp3>, 2> mu;
    out.dual_safe_challenges_replayed =
        DeriveAllMu(
            proof.claim_root,
            static_cast<uint32_t>(claims.size()),
            mu, &why);
    if (!out.dual_safe_challenges_replayed) {
        out.note = why;
        return out;
    }
    const uint256 fri_seed =
        DeriveFriSeed(
            receipt, proof.claim_root,
            proof.batch.groups[1].row_commit.root,
            proof.batch.groups[2].row_commit.root);
    if (fri_seed.IsNull()) {
        out.note =
            "stage3:gkr_mle_adapter:fri_seed";
        return out;
    }
    out.v13_multirow_fri_verified =
        Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
            proof.batch, fri_seed, &why);
    if (!out.v13_multirow_fri_verified) {
        out.note =
            "stage3:gkr_mle_adapter:fri:" + why;
        return out;
    }
    out.dual_evaluation_identities_verified =
        VerifyDualIdentities(
            receipt, claims, proof, mu, &why);
    if (!out.dual_evaluation_identities_verified) {
        out.note = why;
        return out;
    }
    std::vector<unsigned char> encoded;
    const size_t encoded_size =
        SerializeProofV1(proof, encoded);
    out.proof_within_wire_cap =
        encoded_size > 0 &&
        encoded_size == encoded.size() &&
        encoded_size <= kMaxProofBytesV1;
    if (!out.proof_within_wire_cap) {
        out.note =
            "stage3:gkr_mle_adapter:wire_cap";
        return out;
    }
    const auto decoded =
        DeserializeProofV1(encoded);
    std::vector<unsigned char> reencoded;
    out.canonical_codec_round_trip =
        decoded.has_value() &&
        SerializeProofV1(
            *decoded, reencoded) ==
            encoded.size() &&
        reencoded == encoded;
    if (!out.canonical_codec_round_trip) {
        out.note =
            "stage3:gkr_mle_adapter:codec";
        return out;
    }
    out.arbitrary_mle_claims_verified = true;
    out.episode_relation_semantics_verified = false;
    out.recursively_consumed = false;
    out.valid =
        out.receipt_verified &&
        out.canonical_claims &&
        out.claim_transcript_bound &&
        out.receipt_row_root_reused &&
        out.dual_safe_challenges_replayed &&
        out.v13_multirow_fri_verified &&
        out.dual_evaluation_identities_verified &&
        out.canonical_codec_round_trip &&
        out.proof_within_wire_cap &&
        out.arbitrary_mle_claims_verified;
    out.note = out.valid
        ? "stage3:gkr_mle_adapter:"
          "arbitrary_mle_ok;"
          "episode_semantics_and_recursive_"
          "consumption_open"
        : "stage3:gkr_mle_adapter:invalid";
    return out;
}

size_t SerializeProofV1(
    const ProofV1& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (proof.version != kProofVersionV1 ||
        !DigestCanonical(proof.descriptor_root) ||
        !DigestCanonical(proof.receipt_root) ||
        !DigestCanonical(proof.claim_root) ||
        !DigestCanonical(proof.main_row_root) ||
        std::any_of(
            proof.evaluation_argument.sigma.begin(),
            proof.evaluation_argument.sigma.end(),
            [](const gf::Fp3& value) {
                return !Fp3Canonical(value);
            })) {
        return 0;
    }
    std::vector<unsigned char> batch;
    const size_t batch_size =
        SerializeFri3AlgMultiRowBatchProof(
            proof.batch, batch);
    if (batch_size == 0 ||
        batch_size != batch.size() ||
        batch_size >
            std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    out.reserve(224 + batch.size());
    AppendByteU32(out, kProofMagicV1);
    AppendByteU16(out, proof.version);
    AppendByteU16(out, 0);
    AppendByteDigest(out, proof.descriptor_root);
    AppendByteDigest(out, proof.receipt_root);
    AppendByteDigest(out, proof.claim_root);
    AppendByteDigest(out, proof.main_row_root);
    for (const auto& sigma :
         proof.evaluation_argument.sigma) {
        AppendByteFp3(out, sigma);
    }
    for (const uint32_t column :
         proof.evaluation_argument.f_column) {
        AppendByteU32(out, column);
    }
    for (const uint32_t column :
         proof.evaluation_argument.g_column) {
        AppendByteU32(out, column);
    }
    AppendByteU32(
        out, static_cast<uint32_t>(batch.size()));
    out.insert(out.end(), batch.begin(), batch.end());
    if (out.size() > kMaxProofBytesV1) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<ProofV1> DeserializeProofV1(
    const std::vector<unsigned char>& bytes)
{
    // Fixed prefix: 4+2+2 + 4 digests + 2 Fp3 + 4 ids + batch length.
    constexpr size_t FIXED_BYTES =
        4 + 2 + 2 + 4 * 32 + 2 * 24 + 4 * 4 + 4;
    if (bytes.size() < FIXED_BYTES ||
        bytes.size() > kMaxProofBytesV1) {
        return std::nullopt;
    }
    size_t offset = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    ProofV1 out;
    if (!ReadU32(bytes, offset, magic) ||
        !ReadU16(bytes, offset, version) ||
        !ReadU16(bytes, offset, reserved) ||
        magic != kProofMagicV1 ||
        version != kProofVersionV1 ||
        reserved != 0 ||
        !ReadDigest(
            bytes, offset, out.descriptor_root) ||
        !ReadDigest(
            bytes, offset, out.receipt_root) ||
        !ReadDigest(
            bytes, offset, out.claim_root) ||
        !ReadDigest(
            bytes, offset, out.main_row_root)) {
        return std::nullopt;
    }
    out.version = version;
    for (auto& sigma :
         out.evaluation_argument.sigma) {
        if (!ReadFp3(bytes, offset, sigma)) {
            return std::nullopt;
        }
    }
    for (uint32_t& column :
         out.evaluation_argument.f_column) {
        if (!ReadU32(bytes, offset, column)) {
            return std::nullopt;
        }
    }
    for (uint32_t& column :
         out.evaluation_argument.g_column) {
        if (!ReadU32(bytes, offset, column)) {
            return std::nullopt;
        }
    }
    uint32_t batch_size = 0;
    if (!ReadU32(bytes, offset, batch_size) ||
        batch_size == 0 ||
        batch_size != bytes.size() - offset) {
        return std::nullopt;
    }
    std::vector<unsigned char> batch(
        bytes.begin() + offset, bytes.end());
    const auto decoded =
        DeserializeFri3AlgMultiRowBatchProof(batch);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    out.batch = *decoded;
    std::vector<unsigned char> canonical;
    if (SerializeProofV1(out, canonical) !=
            bytes.size() ||
        canonical != bytes) {
        return std::nullopt;
    }
    return out;
}

} // namespace matmul::v4::rc::stage3_gkr_mle_adapter
