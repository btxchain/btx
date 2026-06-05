// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PQKEY_H
#define BITCOIN_PQKEY_H

#include <span.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <array>
#include <optional>
#include <vector>

static constexpr size_t MLDSA44_PUBKEY_SIZE = 1312;
static constexpr size_t MLDSA44_SECRET_KEY_SIZE = 2560;
static constexpr size_t MLDSA44_SIGNATURE_SIZE = 2420;

static constexpr size_t SLHDSA128S_PUBKEY_SIZE = 32;
static constexpr size_t SLHDSA128S_SECRET_KEY_SIZE = 64;
static constexpr size_t SLHDSA128S_SIGNATURE_SIZE = 7856;

enum class PQAlgorithm : uint8_t {
    ML_DSA_44 = 0,
    SLH_DSA_128S = 1,
};

struct PQAlgorithmParams {
    size_t pubkey_size;
    size_t secret_key_size;
    size_t signature_size;
};

const std::array<PQAlgorithm, 2>& GetSupportedPQAlgorithms();
const PQAlgorithmParams& GetPQAlgorithmParams(PQAlgorithm algo);
size_t GetPQPubKeySize(PQAlgorithm algo);
size_t GetPQSecretKeySize(PQAlgorithm algo);
size_t GetPQSignatureSize(PQAlgorithm algo);
std::optional<PQAlgorithm> GetPQAlgorithmByPubKeySize(size_t pubkey_size);

class CPQKey
{
private:
    using SecureByteVec = std::vector<unsigned char, secure_allocator<unsigned char>>;

    PQAlgorithm m_algo{PQAlgorithm::ML_DSA_44};
    secure_unique_ptr<SecureByteVec> m_secret_key;
    std::vector<unsigned char> m_pubkey;
    bool m_valid{false};

public:
    CPQKey();
    ~CPQKey();

    CPQKey(const CPQKey& other);
    CPQKey& operator=(const CPQKey& other);
    CPQKey(CPQKey&&) noexcept = default;
    CPQKey& operator=(CPQKey&&) noexcept = default;

    void MakeNewKey(PQAlgorithm algo);
    bool MakeDeterministicKey(PQAlgorithm algo, Span<const unsigned char> seed_material);
    // slhdsa_fips205: when true and the algorithm is SLH-DSA, the message is
    // preconditioned with the FIPS-205 pure-mode empty-context wrapper
    // (M' = 0x00 || 0x00 || hash) before signing, instead of signing the bare
    // hash (round-3.x SPHINCS+ reference behaviour). No effect for ML-DSA
    // (FIPS-204, which has no SLH-DSA-style context wrapper here). Gated at the
    // consensus activation height by callers; default false = legacy round-3.
    bool Sign(const uint256& hash, std::vector<unsigned char>& sig,
              bool slhdsa_fips205 = false) const;
    std::vector<unsigned char> GetPubKey() const;
    PQAlgorithm GetAlgorithm() const;
    bool IsValid() const;
    void ClearKeyData();
    size_t GetPubKeySize() const;
    size_t GetSigSize() const;
};

class CPQPubKey
{
private:
    PQAlgorithm m_algo;
    std::vector<unsigned char> m_data;

public:
    CPQPubKey(PQAlgorithm algo, Span<const unsigned char> data);

    // slhdsa_fips205: see CPQKey::Sign. When true and the algorithm is SLH-DSA,
    // verifies against the FIPS-205 pure-mode wrapped message; default false =
    // legacy round-3 (bare hash).
    bool Verify(const uint256& hash, Span<const unsigned char> sig,
                bool slhdsa_fips205 = false) const;
    PQAlgorithm GetAlgorithm() const;
    Span<const unsigned char> GetData() const;
    size_t size() const;
};

/**
 * FIPS-205 pure-mode message preconditioning for SLH-DSA with an empty context:
 *   M' = toByte(0,1) || toByte(|ctx|=0,1) || M  =  0x00 || 0x00 || M
 * BTX's SLH-DSA core is the SPHINCS+ round-3.x reference, which signs the bare
 * message; applying this wrapper at the call boundary turns it into FIPS-205
 * SLH-DSA (the SHAKE tweakable-hash chains are identical, so only the message
 * preconditioning differs). Exposed for cross-implementation/KAT tests.
 */
[[nodiscard]] std::vector<unsigned char> Fips205PureContextMessage(const uint256& hash);

#endif // BITCOIN_PQKEY_H
