// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>

#include <crypto/ct_utils.h>
#include <hash.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include <random.h>

#include <array>
#include <algorithm>

namespace {

constexpr std::array<PQAlgorithm, 2> SUPPORTED_PQ_ALGORITHMS{
    PQAlgorithm::ML_DSA_44,
    PQAlgorithm::SLH_DSA_128S,
};

constexpr PQAlgorithmParams MLDSA44_PARAMS{
    MLDSA44_PUBKEY_SIZE,
    MLDSA44_SECRET_KEY_SIZE,
    MLDSA44_SIGNATURE_SIZE,
};

constexpr PQAlgorithmParams SLHDSA128S_PARAMS{
    SLHDSA128S_PUBKEY_SIZE,
    SLHDSA128S_SECRET_KEY_SIZE,
    SLHDSA128S_SIGNATURE_SIZE,
};

constexpr PQAlgorithmParams UNKNOWN_PARAMS{0, 0, 0};

bitcoin_pqc_algorithm_t ToCAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return BITCOIN_PQC_ML_DSA_44;
    case PQAlgorithm::SLH_DSA_128S:
        return BITCOIN_PQC_SLH_DSA_SHAKE_128S;
    }
    return BITCOIN_PQC_ML_DSA_44;
}

} // namespace

const std::array<PQAlgorithm, 2>& GetSupportedPQAlgorithms()
{
    return SUPPORTED_PQ_ALGORITHMS;
}

const PQAlgorithmParams& GetPQAlgorithmParams(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return MLDSA44_PARAMS;
    case PQAlgorithm::SLH_DSA_128S:
        return SLHDSA128S_PARAMS;
    }
    return UNKNOWN_PARAMS;
}

size_t GetPQPubKeySize(PQAlgorithm algo)
{
    return GetPQAlgorithmParams(algo).pubkey_size;
}

size_t GetPQSecretKeySize(PQAlgorithm algo)
{
    return GetPQAlgorithmParams(algo).secret_key_size;
}

size_t GetPQSignatureSize(PQAlgorithm algo)
{
    return GetPQAlgorithmParams(algo).signature_size;
}

std::optional<PQAlgorithm> GetPQAlgorithmByPubKeySize(size_t pubkey_size)
{
    for (const PQAlgorithm algo : GetSupportedPQAlgorithms()) {
        if (GetPQPubKeySize(algo) == pubkey_size) return algo;
    }
    return std::nullopt;
}

CPQKey::CPQKey() : m_secret_key(make_secure_unique<SecureByteVec>()) {}

CPQKey::CPQKey(const CPQKey& other)
    : m_algo(other.m_algo),
      m_secret_key(make_secure_unique<SecureByteVec>(*other.m_secret_key)),
      m_pubkey(other.m_pubkey),
      m_valid(other.m_valid)
{
}

CPQKey& CPQKey::operator=(const CPQKey& other)
{
    if (this == &other) {
        return *this;
    }
    ClearKeyData();
    m_algo = other.m_algo;
    m_pubkey = other.m_pubkey;
    *m_secret_key = *other.m_secret_key;
    m_valid = other.m_valid;
    return *this;
}

CPQKey::~CPQKey()
{
    ClearKeyData();
}

void CPQKey::MakeNewKey(PQAlgorithm algo)
{
    ClearKeyData();

    std::array<unsigned char, 128> entropy{};
    for (size_t offset = 0; offset < entropy.size(); offset += 32) {
        const size_t chunk = std::min<size_t>(32, entropy.size() - offset);
        GetRandBytes(Span<unsigned char>(entropy.data() + offset, chunk));
    }

    bitcoin_pqc_keypair_t keypair{};
    const bitcoin_pqc_error_t result = bitcoin_pqc_keygen(
        ToCAlgo(algo),
        &keypair,
        entropy.data(),
        entropy.size());
    secure_memzero(entropy.data(), entropy.size());

    if (result != BITCOIN_PQC_OK) {
        m_valid = false;
        return;
    }

    m_algo = algo;
    m_pubkey.assign(
        static_cast<const unsigned char*>(keypair.public_key),
        static_cast<const unsigned char*>(keypair.public_key) + keypair.public_key_size);
    m_secret_key->assign(
        static_cast<const unsigned char*>(keypair.secret_key),
        static_cast<const unsigned char*>(keypair.secret_key) + keypair.secret_key_size);
    bitcoin_pqc_keypair_free(&keypair);

    m_valid = (m_pubkey.size() == GetPQPubKeySize(m_algo) &&
               m_secret_key->size() == GetPQSecretKeySize(m_algo));
}

bool CPQKey::MakeDeterministicKey(PQAlgorithm algo, Span<const unsigned char> seed_material)
{
    ClearKeyData();
    if (seed_material.empty()) {
        return false;
    }

    std::array<unsigned char, 128> entropy{};
    uint32_t counter = 0;
    size_t offset = 0;
    while (offset < entropy.size()) {
        const uint256 block = (HashWriter{} << seed_material << counter).GetSHA256();
        const size_t ncopy = std::min<size_t>(block.size(), entropy.size() - offset);
        std::copy(block.begin(), block.begin() + ncopy, entropy.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += ncopy;
        ++counter;
    }

    bitcoin_pqc_keypair_t keypair{};
    const bitcoin_pqc_error_t result = bitcoin_pqc_keygen(
        ToCAlgo(algo),
        &keypair,
        entropy.data(),
        entropy.size());
    secure_memzero(entropy.data(), entropy.size());

    if (result != BITCOIN_PQC_OK) {
        m_valid = false;
        return false;
    }

    m_algo = algo;
    m_pubkey.assign(
        static_cast<const unsigned char*>(keypair.public_key),
        static_cast<const unsigned char*>(keypair.public_key) + keypair.public_key_size);
    m_secret_key->assign(
        static_cast<const unsigned char*>(keypair.secret_key),
        static_cast<const unsigned char*>(keypair.secret_key) + keypair.secret_key_size);
    bitcoin_pqc_keypair_free(&keypair);

    m_valid = (m_pubkey.size() == GetPQPubKeySize(m_algo) &&
               m_secret_key->size() == GetPQSecretKeySize(m_algo));
    return m_valid;
}

bool CPQKey::Sign(const uint256& hash, std::vector<unsigned char>& sig) const
{
    if (!IsValid()) {
        sig.clear();
        return false;
    }

    // Hedged signing entropy mixed by libbitcoinpqc with (secret key || message).
    std::array<unsigned char, 128> entropy{};
    for (size_t offset = 0; offset < entropy.size(); offset += 32) {
        const size_t chunk = std::min<size_t>(32, entropy.size() - offset);
        GetRandBytes(Span<unsigned char>(entropy.data() + offset, chunk));
    }

    bitcoin_pqc_signature_t signature{};
    const bitcoin_pqc_error_t result = bitcoin_pqc_sign_with_randomness(
        ToCAlgo(m_algo),
        m_secret_key->data(),
        m_secret_key->size(),
        hash.data(),
        hash.size(),
        entropy.data(),
        entropy.size(),
        &signature);
    secure_memzero(entropy.data(), entropy.size());
    if (result != BITCOIN_PQC_OK) {
        sig.clear();
        return false;
    }

    sig.assign(signature.signature, signature.signature + signature.signature_size);
    bitcoin_pqc_signature_free(&signature);
    return sig.size() == GetPQSignatureSize(m_algo);
}

std::vector<unsigned char> CPQKey::GetPubKey() const
{
    return m_pubkey;
}

PQAlgorithm CPQKey::GetAlgorithm() const
{
    return m_algo;
}

bool CPQKey::IsValid() const
{
    return m_valid && m_secret_key && !m_secret_key->empty() && !m_pubkey.empty();
}

void CPQKey::ClearKeyData()
{
    if (m_secret_key && !m_secret_key->empty()) {
        secure_memzero(m_secret_key->data(), m_secret_key->size());
        m_secret_key->clear();
        m_secret_key->shrink_to_fit();
    }
    if (!m_pubkey.empty()) {
        secure_memzero(m_pubkey.data(), m_pubkey.size());
        m_pubkey.clear();
        m_pubkey.shrink_to_fit();
    }
    m_valid = false;
}

size_t CPQKey::GetPubKeySize() const
{
    return IsValid() ? GetPQPubKeySize(m_algo) : 0;
}

size_t CPQKey::GetSigSize() const
{
    return IsValid() ? GetPQSignatureSize(m_algo) : 0;
}

CPQPubKey::CPQPubKey(PQAlgorithm algo, Span<const unsigned char> data) : m_algo(algo), m_data(data.begin(), data.end()) {}

bool CPQPubKey::Verify(const uint256& hash, Span<const unsigned char> sig) const
{
    if (m_data.size() != GetPQPubKeySize(m_algo) || sig.size() != GetPQSignatureSize(m_algo)) {
        return false;
    }
    return bitcoin_pqc_verify(
               ToCAlgo(m_algo),
               m_data.data(),
               m_data.size(),
               hash.data(),
               hash.size(),
               sig.data(),
               sig.size()) == BITCOIN_PQC_OK;
}

PQAlgorithm CPQPubKey::GetAlgorithm() const
{
    return m_algo;
}

Span<const unsigned char> CPQPubKey::GetData() const
{
    return Span<const unsigned char>(m_data);
}

size_t CPQPubKey::size() const
{
    return m_data.size();
}
