// MinGW does not provide the POSIX file, process, and socket helpers the
// model plane uses. Exclusive create (O_EXCL) still refuses an existing
// name. lstat reports a reparse point as a symlink so those checks fail
// closed. Process helpers fail closed: fork is not available here, and
// CUDA loader spawn stays unimplemented on Windows.

#ifndef BTX_COMPAT_MINGW_POSIX_EXTRA_H
#define BTX_COMPAT_MINGW_POSIX_EXTRA_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// The other Windows headers model plane files include. They use macros
// removed below (VOID, CALLBACK, interface), so they are read first.
#include <aclapi.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <sddl.h>
#include <userenv.h>

// Windows headers macro-define identifiers the node and the lab use as enums.
#ifdef STRICT
#undef STRICT
#endif
#ifdef IGNORE
#undef IGNORE
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef IN
#undef IN
#endif
#ifdef OUT
#undef OUT
#endif
#ifdef OPTIONAL
#undef OPTIONAL
#endif
#ifdef DIFFERENCE
#undef DIFFERENCE
#endif
#ifdef ABSOLUTE
#undef ABSOLUTE
#endif
#ifdef RELATIVE
#undef RELATIVE
#endif
#ifdef DELETE
#undef DELETE
#endif
#ifdef CONST
#undef CONST
#endif
#ifdef VOID
#undef VOID
#endif
#ifdef CALLBACK
#undef CALLBACK
#endif
#ifdef interface
#undef interface
#endif
#ifdef near
#undef near
#endif
#ifdef far
#undef far
#endif
#ifdef pascal
#undef pascal
#endif

#include <csignal>
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGPIPE
#define SIGPIPE 13
#endif
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif
#ifndef nfds_t
#define nfds_t unsigned long
#endif

#include <cerrno>
#include <cstddef>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef _UID_T_
#define _UID_T_
typedef unsigned int uid_t;
#endif

#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & _S_IFMT) == S_IFLNK)
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & _S_IFMT) == S_IFSOCK)
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x4000
#endif
#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef F_SETFL
#define F_SETFL 4
#endif
#ifndef F_SETFD
#define F_SETFD 2
#endif
#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef WNOHANG
#define WNOHANG 1
#endif
#ifndef WUNTRACED
#define WUNTRACED 2
#endif
#ifndef WIFEXITED
#define WIFEXITED(s) (((s) & 0x7f) == 0)
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(s) (((s) & 0x7f) > 0 && ((s) & 0x7f) < 0x7f)
#endif
#ifndef WTERMSIG
#define WTERMSIG(s) ((s) & 0x7f)
#endif

inline int btx_lstat(const char* path, struct stat* st)
{
    if (path == nullptr || st == nullptr) {
        errno = EINVAL;
        return -1;
    }
    wchar_t wpath[32768];
    const int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, static_cast<int>(sizeof(wpath) / sizeof(wpath[0])));
    DWORD attr = INVALID_FILE_ATTRIBUTES;
    if (n > 0) attr = GetFileAttributesW(wpath);
    if (stat(path, st) != 0) {
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            std::memset(st, 0, sizeof(*st));
            st->st_mode = S_IFLNK;
            return 0;
        }
        return -1;
    }
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        st->st_mode = (st->st_mode & ~_S_IFMT) | S_IFLNK;
    }
    return 0;
}

inline int btx_fork()
{
    errno = ENOSYS;
    return -1;
}

inline int btx_pipe(int fds[2])
{
    return _pipe(fds, 4096, _O_BINARY);
}

inline ssize_t btx_pread(int fd, void* buf, size_t n, long long off)
{
    const long long cur = _lseeki64(fd, 0, SEEK_CUR);
    if (cur < 0) return -1;
    if (_lseeki64(fd, off, SEEK_SET) < 0) return -1;
    const int r = _read(fd, buf, static_cast<unsigned>(n));
    _lseeki64(fd, cur, SEEK_SET);
    return r;
}

inline ssize_t btx_pwrite(int fd, const void* buf, size_t n, long long off)
{
    const long long cur = _lseeki64(fd, 0, SEEK_CUR);
    if (cur < 0) return -1;
    if (_lseeki64(fd, off, SEEK_SET) < 0) return -1;
    const int r = _write(fd, buf, static_cast<unsigned>(n));
    _lseeki64(fd, cur, SEEK_SET);
    return r;
}

inline char* btx_mkdtemp(char* tmpl)
{
    if (_mktemp(tmpl) == nullptr) return nullptr;
    if (!CreateDirectoryA(tmpl, nullptr)) {
        errno = EEXIST;
        return nullptr;
    }
    return tmpl;
}

inline int btx_getuid()
{
    return 0;
}

inline int btx_fchmod(int, int)
{
    errno = ENOSYS;
    return -1;
}

inline int btx_fsync(int fd)
{
    return _commit(fd);
}

inline int btx_fcntl(int fd, int cmd, int arg = 0)
{
    if (cmd == F_GETFL) return 0;
    if (cmd == F_SETFL) {
        u_long nb = (arg & O_NONBLOCK) != 0 ? 1UL : 0UL;
        ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &nb);
        return 0;
    }
    (void)fd;
    (void)arg;
    return 0;
}

inline int btx_kill(int, int)
{
    errno = ENOSYS;
    return -1;
}

inline int btx_waitpid(int, int* status, int)
{
    if (status != nullptr) *status = 0;
    errno = ECHILD;
    return -1;
}

inline int btx_setpgid(int, int)
{
    errno = ENOSYS;
    return -1;
}

// getenv reads the C runtime's copy of the environment, which
// SetEnvironmentVariableA does not change. _putenv_s changes that copy and
// the process environment together, and an empty value removes the name.
inline int setenv(const char* name, const char* value, int overwrite)
{
    if (overwrite == 0 && getenv(name) != nullptr) return 0;
    return _putenv_s(name, value) == 0 ? 0 : -1;
}

inline int unsetenv(const char* name)
{
    return _putenv_s(name, "") == 0 ? 0 : -1;
}

inline struct tm* btx_gmtime_r(const time_t* t, struct tm* out)
{
    return gmtime_s(out, t) == 0 ? out : nullptr;
}

inline int open(const wchar_t* path, int flags, int mode = 0)
{
    return _wopen(path, flags, mode);
}

inline int unlink(const wchar_t* path)
{
    return _wunlink(path);
}

inline int chmod(const wchar_t* path, int mode)
{
    return _wchmod(path, mode);
}

inline int access(const wchar_t* path, int mode)
{
    return _waccess(path, mode);
}

inline int btx_lstat(const wchar_t* path, struct stat* st)
{
    if (path == nullptr || st == nullptr) {
        errno = EINVAL;
        return -1;
    }
    char narrow[32768];
    const int n = WideCharToMultiByte(CP_UTF8, 0, path, -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
    if (n <= 0) {
        errno = EINVAL;
        return -1;
    }
    return btx_lstat(narrow, st);
}

template <typename OptLen>
inline int btx_setsockopt(SOCKET s, int level, int optname, const void* optval, OptLen optlen)
{
    return (setsockopt)(s, level, optname, static_cast<const char*>(optval), static_cast<int>(optlen));
}

inline int btx_getsockopt(SOCKET s, int level, int optname, void* optval, int* optlen)
{
    return (getsockopt)(s, level, optname, static_cast<char*>(optval), optlen);
}

inline int btx_connect(SOCKET s, const struct sockaddr* addr, int len)
{
    const int r = (connect)(s, addr, len);
    if (r != 0) {
        const int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS) errno = EINPROGRESS;
        else errno = e;
    }
    return r;
}

inline int btx_send(SOCKET s, const void* buf, int len, int flags)
{
    return (send)(s, static_cast<const char*>(buf), len, flags);
}

inline int btx_recv(SOCKET s, void* buf, int len, int flags)
{
    return (recv)(s, static_cast<char*>(buf), len, flags);
}

inline int btx_sendto(SOCKET s, const void* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    return (sendto)(s, static_cast<const char*>(buf), len, flags, to, tolen);
}

inline int btx_recvfrom(SOCKET s, void* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    return (recvfrom)(s, static_cast<char*>(buf), len, flags, from, fromlen);
}

// Winsock has no AF_UNIX socketpair. Callers see a failed socketpair.
inline int btx_socketpair(int, int, int, int*)
{
    errno = ENOSYS;
    return -1;
}

#define lstat(...) btx_lstat(__VA_ARGS__)
#define fork() btx_fork()
#define pipe(...) btx_pipe(__VA_ARGS__)
#define pread(...) btx_pread(__VA_ARGS__)
#define pwrite(...) btx_pwrite(__VA_ARGS__)
#define mkdtemp(...) btx_mkdtemp(__VA_ARGS__)
#define getuid() btx_getuid()
#define fchmod(...) btx_fchmod(__VA_ARGS__)
#define fsync(...) btx_fsync(__VA_ARGS__)
#define fcntl(...) btx_fcntl(__VA_ARGS__)
#define kill(...) btx_kill(__VA_ARGS__)
#define waitpid(...) btx_waitpid(__VA_ARGS__)
#define setpgid(...) btx_setpgid(__VA_ARGS__)
#define gmtime_r(t, out) btx_gmtime_r((t), (out))
#define setsockopt(...) btx_setsockopt(__VA_ARGS__)
#define getsockopt(...) btx_getsockopt(__VA_ARGS__)
#define connect(...) btx_connect(__VA_ARGS__)
#define send(...) btx_send(__VA_ARGS__)
#define recv(...) btx_recv(__VA_ARGS__)
#define sendto(...) btx_sendto(__VA_ARGS__)
#define recvfrom(...) btx_recvfrom(__VA_ARGS__)
#define socketpair(...) btx_socketpair(__VA_ARGS__)

#endif // _WIN32
#endif
