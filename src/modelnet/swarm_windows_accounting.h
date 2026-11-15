// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifndef BTX_MODELNET_SWARM_WINDOWS_ACCOUNTING_H
#define BTX_MODELNET_SWARM_WINDOWS_ACCOUNTING_H

#ifdef _WIN32
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet::windows_accounting {

inline constexpr uint64_t MAX_OUTPUT_BYTES = 64ULL * 1024 * 1024;

inline bool LiveTreeBudget(uint64_t input, uint64_t& out)
{
    if (input > (std::numeric_limits<uint64_t>::max)() - MAX_OUTPUT_BYTES) return false;
    out = input + MAX_OUTPUT_BYTES;
    return true;
}

enum class CpuState { within, over_limit, invalid };

inline CpuState EvaluateCpu(LONGLONG user, LONGLONG kernel, uint64_t budget_ticks)
{
    if (user < 0 || kernel < 0) return CpuState::invalid;
    const auto u = static_cast<uint64_t>(user);
    const auto k = static_cast<uint64_t>(kernel);
    // Subtraction avoids overflowing the sum. Equality is permitted.
    return u > budget_ticks || k > budget_ticks - u ? CpuState::over_limit : CpuState::within;
}

enum class TreeState { within, over_limit, incomplete, failure, interrupted };

struct TreeResult {
    TreeState state{TreeState::failure};
    DWORD error{ERROR_SUCCESS};
    uint64_t bytes{0};
    size_t entries{0};
};

/** Metadata-only sample of one owned staged root, not an atomic disk quota.
 *
 * Calls are serial. Each pass restarts enumeration and owns all descendant
 * handles/buffers. Incomplete passes must not be used as a successful sample;
 * the supervisor may restart once while retaining its original CPU/wall clocks.
 * No filesystem-name allowlist or pathname traversal fallback is used.
 */
class TreeSampler {
    class Handle {
        HANDLE m_value{INVALID_HANDLE_VALUE};
        bool m_owned{true};
    public:
        Handle() = default;
        explicit Handle(HANDLE value, bool owned = true) : m_value(value), m_owned(owned) {}
        ~Handle() { if (Valid() && m_owned) CloseHandle(m_value); }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        Handle(Handle&& other) noexcept : m_value(other.m_value), m_owned(other.m_owned)
        {
            other.m_value = INVALID_HANDLE_VALUE;
        }
        Handle& operator=(Handle&& other) noexcept
        {
            if (this != &other) {
                if (Valid() && m_owned) CloseHandle(m_value);
                m_value = other.m_value;
                m_owned = other.m_owned;
                other.m_value = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
        bool Valid() const { return m_value != INVALID_HANDLE_VALUE && m_value != nullptr; }
        HANDLE Get() const { return m_value; }
    };

    static constexpr size_t MAX_ENTRIES = 8192;
    static constexpr size_t MAX_ENTRY_DEPTH = 64;
    static constexpr size_t BUFFER_BYTES = 64 * 1024;

    struct Frame {
        Handle directory;
        size_t depth;
        // Heap storage keeps deep trees off the Windows thread stack. ULONG64
        // provides sufficient alignment for FILE_ID_BOTH_DIR_INFO records.
        std::vector<ULONG64> buffer;
        size_t offset{0};
        bool restart{true};
        bool need_batch{true};

        Frame(Handle handle, size_t entry_depth)
            : directory(std::move(handle)), depth(entry_depth), buffer(BUFFER_BYTES / sizeof(ULONG64)) {}
        Frame(Frame&&) noexcept = default;
        Frame& operator=(Frame&&) noexcept = default;
        Frame(const Frame&) = delete;
        Frame& operator=(const Frame&) = delete;
    };

    Handle m_root;
    std::wstring m_anchor;
    DWORD m_volume;
    uint64_t m_root_id;

    TreeSampler(Handle root, std::wstring anchor, DWORD volume, uint64_t id)
        : m_root(std::move(root)), m_anchor(std::move(anchor)), m_volume(volume), m_root_id(id) {}

    static uint64_t Id(const BY_HANDLE_FILE_INFORMATION& info)
    {
        return (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    }

    static DWORD LastError()
    {
        const DWORD error = GetLastError();
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
    }

    static TreeState ApiFailureState(DWORD error)
    {
        // An ambiguous denial is not a harmless missing entry or zero usage.
        // Return the entire pass as incomplete; a persistent denial refuses.
        switch (error) {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_DELETE_PENDING:
        case ERROR_SHARING_VIOLATION:
        case ERROR_ACCESS_DENIED:
            return TreeState::incomplete;
        default:
            return TreeState::failure;
        }
    }

    static bool FinalPath(HANDLE handle, std::wstring& path, DWORD& error)
    {
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetFinalPathNameByHandleW(handle, buffer.data(),
            static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (length == 0) { error = LastError(); return false; }
        if (length >= buffer.size()) { error = ERROR_FILENAME_EXCED_RANGE; return false; }
        path.assign(buffer.data(), length);
        while (path.size() > 4 && path.back() == L'\\') path.pop_back();
        error = ERROR_SUCCESS;
        return true;
    }

    static bool EqualPath(const std::wstring& left, const std::wstring& right)
    {
        return left.size() == right.size() &&
            CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
                right.data(), static_cast<int>(right.size()), FALSE) == CSTR_EQUAL;
    }

    bool BelowRoot(const std::wstring& path) const
    {
        return path.size() > m_anchor.size() && path[m_anchor.size()] == L'\\' &&
            CompareStringOrdinal(path.data(), static_cast<int>(m_anchor.size()),
                m_anchor.data(), static_cast<int>(m_anchor.size()), FALSE) == CSTR_EQUAL;
    }

public:
    ~TreeSampler() = default;
    TreeSampler(const TreeSampler&) = delete;
    TreeSampler& operator=(const TreeSampler&) = delete;

    static std::unique_ptr<TreeSampler> Create(const std::wstring& root, DWORD& error)
    {
        Handle handle(CreateFileW(root.c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!handle.Valid()) { error = LastError(); return {}; }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle.Get(), &info)) { error = LastError(); return {}; }
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || Id(info) == 0) {
            error = ERROR_INVALID_DATA;
            return {};
        }
        std::wstring anchor;
        if (!FinalPath(handle.Get(), anchor, error)) return {};
        error = ERROR_SUCCESS;
        return std::unique_ptr<TreeSampler>(new TreeSampler(
            std::move(handle), std::move(anchor), info.dwVolumeSerialNumber, Id(info)));
    }

    TreeResult Sample(uint64_t cap, const std::function<bool()>& keep_running) const
    {
        TreeResult result{TreeState::within, ERROR_SUCCESS, 0, 0};
        const auto stopped = [&] {
            if (!keep_running || keep_running()) return false;
            result.state = TreeState::interrupted;
            result.error = ERROR_CANCELLED;
            return true;
        };
        const auto failed = [&](DWORD error) {
            result.state = ApiFailureState(error);
            result.error = error;
        };

        if (stopped()) return result;
        BY_HANDLE_FILE_INFORMATION root_info{};
        if (!GetFileInformationByHandle(m_root.Get(), &root_info)) { failed(LastError()); return result; }
        if (stopped()) return result;
        if (root_info.dwVolumeSerialNumber != m_volume || Id(root_info) != m_root_id ||
            !(root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            result.state = TreeState::failure; result.error = ERROR_INVALID_DATA; return result;
        }
        std::wstring current_anchor;
        DWORD error = ERROR_SUCCESS;
        if (stopped()) return result;
        if (!FinalPath(m_root.Get(), current_anchor, error)) { failed(error); return result; }
        if (stopped()) return result;
        if (!EqualPath(current_anchor, m_anchor)) {
            result.state = TreeState::incomplete; result.error = ERROR_RETRY; return result;
        }

        std::set<uint64_t> seen{m_root_id};
        std::vector<Frame> stack;
        // Snapshot counts root entries at depth0. An empty terminal directory
        // can therefore retain a depth65 frame without accepting depth65 entries.
        stack.reserve(MAX_ENTRY_DEPTH + 2);
        stack.emplace_back(Handle(m_root.Get(), false), 0);
        size_t batches = 0;
        while (!stack.empty()) {
            if (stopped()) return result;
            Frame& frame = stack.back();
            if (frame.need_batch) {
                std::wstring directory_path;
                if (!FinalPath(frame.directory.Get(), directory_path, error)) { failed(error); return result; }
                if (stopped()) return result;
                if (frame.depth == 0 ? !EqualPath(directory_path, m_anchor) : !BelowRoot(directory_path)) {
                    result.state = TreeState::failure; result.error = ERROR_ACCESS_DENIED; return result;
                }
                if (++batches > MAX_ENTRIES * 2 + 2) {
                    result.state = TreeState::over_limit; result.error = ERROR_BUFFER_OVERFLOW; return result;
                }
                const auto kind = frame.restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
                const BOOL ok = GetFileInformationByHandleEx(frame.directory.Get(), kind,
                    frame.buffer.data(), static_cast<DWORD>(BUFFER_BYTES));
                const DWORD api_error = ok ? ERROR_SUCCESS : LastError();
                if (stopped()) return result;
                if (!ok) {
                    if (api_error == ERROR_NO_MORE_FILES) { stack.pop_back(); continue; }
                    failed(api_error); return result;
                }
                frame.restart = false; frame.need_batch = false; frame.offset = 0;
            }

            const size_t offset = frame.offset;
            if (offset % alignof(FILE_ID_BOTH_DIR_INFO) != 0 ||
                offset > BUFFER_BYTES - offsetof(FILE_ID_BOTH_DIR_INFO, FileName)) {
                result.state = TreeState::failure; result.error = ERROR_INVALID_DATA; return result;
            }
            const auto* bytes = reinterpret_cast<const unsigned char*>(frame.buffer.data());
            const auto* entry = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(bytes + offset);
            if (entry->FileNameLength == 0 || entry->FileNameLength % sizeof(wchar_t) != 0 ||
                entry->FileNameLength > BUFFER_BYTES - offset - offsetof(FILE_ID_BOTH_DIR_INFO, FileName) ||
                (entry->NextEntryOffset != 0 &&
                    (entry->NextEntryOffset < offsetof(FILE_ID_BOTH_DIR_INFO, FileName) + entry->FileNameLength ||
                     entry->NextEntryOffset % alignof(FILE_ID_BOTH_DIR_INFO) != 0 ||
                     entry->NextEntryOffset > BUFFER_BYTES - offset))) {
                result.state = TreeState::failure; result.error = ERROR_INVALID_DATA; return result;
            }
            const std::wstring name(entry->FileName, entry->FileNameLength / sizeof(wchar_t));
            const DWORD attributes = entry->FileAttributes;
            const LARGE_INTEGER file_id = entry->FileId;
            const size_t depth = frame.depth;
            // Advance the parent before potentially pushing a child frame.
            if (entry->NextEntryOffset == 0) frame.need_batch = true;
            else frame.offset += entry->NextEntryOffset;
            if (name == L"." || name == L"..") continue;

            if (++result.entries > MAX_ENTRIES || depth > MAX_ENTRY_DEPTH) {
                result.state = TreeState::over_limit; result.error = ERROR_BUFFER_OVERFLOW; return result;
            }
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) || file_id.QuadPart == 0) {
                result.state = TreeState::failure; result.error = ERROR_INVALID_DATA; return result;
            }
            const bool directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            FILE_ID_DESCRIPTOR descriptor{};
            descriptor.dwSize = sizeof(descriptor); descriptor.Type = FileIdType; descriptor.FileId = file_id;
            if (stopped()) return result;
            Handle item(OpenFileById(m_root.Get(), &descriptor, directory ? FILE_LIST_DIRECTORY : 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT));
            const DWORD open_error = item.Valid() ? ERROR_SUCCESS : LastError();
            if (stopped()) return result;
            if (!item.Valid()) { failed(open_error); return result; }

            BY_HANDLE_FILE_INFORMATION info{};
            if (stopped()) return result;
            if (!GetFileInformationByHandle(item.Get(), &info)) { failed(LastError()); return result; }
            if (stopped()) return result;
            if (info.dwVolumeSerialNumber != m_volume || Id(info) != static_cast<uint64_t>(file_id.QuadPart) ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
                ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) {
                result.state = TreeState::failure; result.error = ERROR_INVALID_DATA; return result;
            }
            std::wstring path;
            if (stopped()) return result;
            if (!FinalPath(item.Get(), path, error)) { failed(error); return result; }
            if (stopped()) return result;
            if (!BelowRoot(path)) {
                result.state = TreeState::failure; result.error = ERROR_ACCESS_DENIED; return result;
            }
            if (!seen.emplace(Id(info)).second) {
                result.state = TreeState::incomplete; result.error = ERROR_RETRY; return result;
            }
            if (directory) {
                stack.emplace_back(std::move(item), depth + 1);
                continue;
            }

            FILE_STANDARD_INFO standard{};
            if (stopped()) return result;
            if (!GetFileInformationByHandleEx(item.Get(), FileStandardInfo, &standard, sizeof(standard))) {
                failed(LastError()); return result;
            }
            if (stopped()) return result;
            if (standard.DeletePending) {
                result.state = TreeState::incomplete; result.error = ERROR_DELETE_PENDING; return result;
            }
            if (standard.Directory || standard.NumberOfLinks != 1 || standard.EndOfFile.QuadPart < 0) {
                result.state = TreeState::failure; result.error = ERROR_INVALID_DATA; return result;
            }
            const uint64_t length = static_cast<uint64_t>(standard.EndOfFile.QuadPart);
            if (length > cap - result.bytes) {
                result.state = TreeState::over_limit; result.error = ERROR_FILE_TOO_LARGE; return result;
            }
            result.bytes += length;
        }
        return result;
    }
};

} // namespace modelnet::windows_accounting
#endif // _WIN32
#endif // BTX_MODELNET_SWARM_WINDOWS_ACCOUNTING_H
