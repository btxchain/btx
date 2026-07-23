// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_freivalds.h>

#include <crypto/common.h>
#include <matmul/matmul_v4_rc_fri_ext3.h> // Sha256dBytes (SHA256d counter-XOF)

#include <cstring>
#include <string>
#include <vector>

namespace matmul::v4::rc {

namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Fp;
using gkr_field::FromChallengeBytes;
using gkr_field::FromSigned;
using gkr_field::Mul;

} // namespace

std::vector<Fp> FreivaldsChallengeVector(const uint256& challenge_seed,
                                         uint32_t rep, uint32_t n)
{
    // Preimage layout (frozen): seed[32] ‖ "BTX_RC_FRV_V1" ‖ LE32(rep) ‖ LE32(j).
    constexpr size_t kTagLen = sizeof(kRCFreivaldsDomainTag) - 1; // no NUL
    std::vector<unsigned char> buf(32 + kTagLen + 4 + 4);
    std::memcpy(buf.data(), challenge_seed.data(), 32);
    std::memcpy(buf.data() + 32, kRCFreivaldsDomainTag, kTagLen);
    WriteLE32(buf.data() + 32 + kTagLen, rep);
    std::vector<Fp> r(n);
    for (uint32_t j = 0; j < n; ++j) {
        WriteLE32(buf.data() + 32 + kTagLen + 4, j);
        // Low 8 LE digest bytes reduced mod p (gkr_field::FromChallengeBytes).
        r[j] = FromChallengeBytes(Sha256dBytes(buf.data(), buf.size()).data());
    }
    return r;
}

bool FreivaldsCheckGemm(const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                        const std::vector<int64_t>& Y, uint32_t m, uint32_t k,
                        uint32_t n, const uint256& challenge_seed, uint32_t reps,
                        std::string* why)
{
    const auto fail = [why](const char* msg) {
        if (why) *why = msg;
        return false;
    };
    // Fail-closed shape validation (64-bit products: m,k,n are uint32).
    const uint64_t mk = static_cast<uint64_t>(m) * k;
    const uint64_t kn = static_cast<uint64_t>(k) * n;
    const uint64_t mn = static_cast<uint64_t>(m) * n;
    if (A.size() != mk) return fail("freivalds: A.size() != m*k");
    if (B.size() != kn) return fail("freivalds: B.size() != k*n");
    if (Y.size() != mn) return fail("freivalds: Y.size() != m*n");
    if (reps == 0) return fail("freivalds: reps must be >= 1");

    for (uint32_t rep = 0; rep < reps; ++rep) {
        const std::vector<Fp> r = FreivaldsChallengeVector(challenge_seed, rep, n);

        // s = B·r ∈ F^k — O(kn).
        std::vector<Fp> s(k, 0);
        for (uint32_t i = 0; i < k; ++i) {
            const int8_t* row = B.data() + static_cast<size_t>(i) * n;
            Fp acc = 0;
            for (uint32_t j = 0; j < n; ++j) {
                acc = Add(acc, Mul(FromSigned(row[j]), r[j]));
            }
            s[i] = acc;
        }

        // Per row i of A and Y: compare (A·s)_i = (A·(B·r))_i against (Y·r)_i
        // — O(mk + mn) total. A·B is never formed.
        for (uint32_t i = 0; i < m; ++i) {
            const int8_t* arow = A.data() + static_cast<size_t>(i) * k;
            Fp lhs = 0;
            for (uint32_t t = 0; t < k; ++t) {
                lhs = Add(lhs, Mul(FromSigned(arow[t]), s[t]));
            }
            const int64_t* yrow = Y.data() + static_cast<size_t>(i) * n;
            Fp rhs = 0;
            for (uint32_t j = 0; j < n; ++j) {
                rhs = Add(rhs, Mul(FromSigned(yrow[j]), r[j]));
            }
            if (Canonical(lhs) != Canonical(rhs)) {
                if (why) {
                    *why = "freivalds: projection mismatch at rep " +
                           std::to_string(rep) + ", row " + std::to_string(i);
                }
                return false;
            }
        }
    }
    return true;
}

} // namespace matmul::v4::rc
