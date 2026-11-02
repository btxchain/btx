// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_CONTRIB_RC_PROVER_TOKEN_FILE_H
#define BITCOIN_CONTRIB_RC_PROVER_TOKEN_FILE_H

#include <cerrno>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include "token_acl_apple.h"
#endif
#endif

namespace rc_prover {
#ifdef _WIN32
class FileHandle {
public:
    HANDLE value{INVALID_HANDLE_VALUE};
    explicit FileHandle(HANDLE handle) : value(handle) {}
    ~FileHandle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
};
inline void CheckTokenAcl(HANDLE file)
{
    FileHandle process_token{nullptr};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &process_token.value)) throw std::runtime_error("cannot inspect token-file user");
    DWORD size{0};
    GetTokenInformation(process_token.value, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> user(size);
    if (!size || !GetTokenInformation(process_token.value, TokenUser, user.data(), size, &size)) throw std::runtime_error("cannot inspect token-file user");
    PSID current{reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid};
    unsigned char system[SECURITY_MAX_SID_SIZE], admins[SECURITY_MAX_SID_SIZE];
    DWORD system_size{sizeof(system)}, admins_size{sizeof(admins)};
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &system_size) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &admins_size)) throw std::runtime_error("cannot inspect token-file principals");
    const auto trusted = [&](PSID sid) {
        return sid && (EqualSid(sid, current) || EqualSid(sid, system) || EqualSid(sid, admins));
    };
    PSID owner{nullptr};
    PACL dacl{nullptr};
    PSECURITY_DESCRIPTOR descriptor{nullptr};
    if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) throw std::runtime_error("cannot inspect token-file ACL");
    struct FreeDescriptor { PSECURITY_DESCRIPTOR value; ~FreeDescriptor() { LocalFree(value); } } free_descriptor{descriptor};
    if (!trusted(owner) || !dacl) throw std::runtime_error("token file must have a private owner and DACL");
    for (DWORD i{0}; i < dacl->AceCount; ++i) {
        void* raw{nullptr};
        if (!GetAce(dacl, i, &raw)) throw std::runtime_error("cannot inspect token-file ACE");
        const auto* header{static_cast<ACE_HEADER*>(raw)};
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) throw std::runtime_error("unsupported token-file ACL; use a private explicit DACL");
        const auto* ace{static_cast<ACCESS_ALLOWED_ACE*>(raw)};
        constexpr DWORD sensitive{FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_READ | GENERIC_WRITE | GENERIC_ALL};
        if ((ace->Mask & sensitive) && !trusted(const_cast<DWORD*>(&ace->SidStart))) throw std::runtime_error("token-file ACL grants access to another principal");
    }
}
#endif

/** Inspect and read the same opened regular file; never log token contents. */
inline std::string LoadPrivateToken(const std::filesystem::path& path)
{
    std::string token;
    char buffer[4099];
#ifdef _WIN32
    // Refuse reparse points and prevent concurrent writers/replacement while read.
    FileHandle file{CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (file.value == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open token file");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.value, &info) || GetFileType(file.value) != FILE_TYPE_DISK ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) throw std::runtime_error("token file must be a regular non-reparse file");
    CheckTokenAcl(file.value);
    DWORD count{0};
    if (!ReadFile(file.value, buffer, sizeof(buffer), &count, nullptr)) throw std::runtime_error("cannot read token file");
    token.assign(buffer, count);
#else
    const int fd{open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
    if (fd < 0) throw std::runtime_error("cannot open token file");
    struct CloseFile { int value; ~CloseFile() { close(value); } } file{fd};
    struct stat info{};
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0077)) throw std::runtime_error("token file must be owned by this user with mode 0600 or 0400");
#ifdef __APPLE__
    CheckAppleTokenAcl(fd);
#endif
    for (;;) {
        const ssize_t count{read(fd, buffer, sizeof(buffer))};
        if (count < 0) { if (errno == EINTR) continue; throw std::runtime_error("cannot read token file"); }
        if (count == 0) break;
        token.append(buffer, static_cast<size_t>(count));
        if (token.size() >= sizeof(buffer)) break;
    }
#endif
    if (token.size() >= sizeof(buffer)) throw std::runtime_error("token file too large");
    while (!token.empty() && (token.back() == '\r' || token.back() == '\n')) token.pop_back();
    if (token.size() < 32 || token.size() > 4096) throw std::runtime_error("token must contain 32..4096 bytes");
    return token;
}
} // namespace rc_prover
#endif
