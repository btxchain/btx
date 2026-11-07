// Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_COMMON_H
#define BITCOIN_MODELNET_SECURITY_V2_COMMON_H
#include <univalue.h>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace modelnet::security {
using Bytes = std::vector<unsigned char>;
using Json = UniValue;
namespace fs = std::filesystem;
constexpr size_t MAX_RECORD = 1024 * 1024;
constexpr size_t MAX_SIGNATURES = 16;
constexpr size_t PK_BYTES = 1312, SK_BYTES = 2560, SIG_BYTES = 2420;
class Error : public std::runtime_error {
public:
    explicit Error(std::string code) : std::runtime_error(code), code(std::move(code)) {}
    const std::string code;
};
void Require(bool condition, const char* code);
int64_t NowMs();
fs::path NativePath(std::string_view text);
std::string Hex(std::span<const unsigned char> bytes);
Bytes Unhex(std::string_view value, size_t max_bytes = MAX_RECORD);
bool IsHash(std::string_view value);
std::string Hash(std::span<const unsigned char> bytes);
std::string Hash(std::string_view text);
std::string DomainHash(std::string_view domain, std::string_view payload);
Bytes RandomBytes(size_t bytes);
void Cleanse(Bytes& bytes) noexcept;
struct KeyPair {
    Bytes public_key; Bytes secret_key;
    KeyPair()=default;
    KeyPair(Bytes public_key,Bytes secret_key):public_key(std::move(public_key)),secret_key(std::move(secret_key)){}
    KeyPair(const KeyPair&)=delete;
    KeyPair& operator=(const KeyPair&)=delete;
    KeyPair(KeyPair&&)=default;
    KeyPair& operator=(KeyPair&& other) noexcept {
        if (this != &other) {
            Cleanse(secret_key);
            public_key = std::move(other.public_key);
            secret_key = std::move(other.secret_key);
        }
        return *this;
    }
    ~KeyPair(){Cleanse(secret_key);}
};
KeyPair GenerateKey();
std::string KeyId(std::span<const unsigned char> public_key);
std::string Sign(std::string_view kind, const Json& body, std::span<const unsigned char> secret);
bool Verify(std::string_view kind, const Json& body, std::span<const unsigned char> public_key,
            std::span<const unsigned char> signature);
/** BTX canonical JSON v1: UTF-8, sorted keys, no duplicates, integers only.
 * Not RFC 8785/JCS. The format name/version is part of every signed message. */
std::string Canonical(const Json& value);
Json Parse(std::string_view input, size_t max_bytes = MAX_RECORD);
Json Object();
Json Array();
Json Strings(const std::vector<std::string>& values);
std::vector<std::string> StringArray(const Json& value, size_t max_items = 256);
void Fields(const Json& value, std::initializer_list<std::string_view> required,
            std::initializer_list<std::string_view> optional = {});
std::string Text(const Json& value, std::string_view name, size_t max_bytes = 4096);
uint64_t UInt(const Json& value, std::string_view name, uint64_t maximum = UINT64_MAX);
bool Boolean(const Json& value, std::string_view name);
std::string DigestField(const Json& value, std::string_view name);
Json Envelope(std::string_view kind, const Json& body);
void AddSignature(Json& envelope, const KeyPair& key);
std::string RecordId(const Json& envelope);
void ValidateEnvelope(const Json& envelope);
bool IsPortablePath(std::string_view path);
bool IsCredentialPath(std::string_view path);
std::string ReadFile(const fs::path& path, uint64_t limit = MAX_RECORD, bool private_file = false);
void WritePrivate(const fs::path& path, std::string_view bytes, bool replace = false);
void EnsurePrivateDirectory(const fs::path& path);
Json Failure(std::string_view code);
} // namespace modelnet::security
#endif
