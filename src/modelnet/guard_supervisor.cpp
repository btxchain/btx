// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#include <modelnet/guard_supervisor.h>
#include <modelnet/guard_machine.h>
#ifdef BTX_MODEL_SECURITY_V2
#include <modelnet/security_v2/database.h>
#endif
#include <algorithm>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>
#include <cerrno>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif
namespace modelnet {
namespace {
using Clock = std::chrono::steady_clock;
constexpr auto EXCHANGE_TIMEOUT = std::chrono::milliseconds(500);
#ifndef _WIN32
void CloseFd(int& fd) { if (fd >= 0) close(fd); fd = -1; }
// Block SIGPIPE only on this calling thread. A dead child must produce EPIPE,
// never terminate the owning node. Preserve any signal pending beforehand.
ssize_t WritePipe(int fd, const char* data, size_t length)
{
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked); sigaddset(&blocked, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &blocked, &previous) != 0) { errno=EIO; return -1; }
    sigpending(&pending);
    const bool already_pending=sigismember(&pending,SIGPIPE)==1;
    ssize_t written;
    do { written=write(fd,data,length); } while (written<0 && errno==EINTR);
    const int saved=errno;
    if (written<0 && saved==EPIPE && !already_pending) {
        sigpending(&pending);
        if (sigismember(&pending,SIGPIPE)==1) { int signal=0; sigwait(&blocked,&signal); }
    }
    pthread_sigmask(SIG_SETMASK,&previous,nullptr);
    errno=saved; return written;
}
#else
void CloseHandleOwned(HANDLE& handle) { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); handle = nullptr; }
#endif
}
fs::path FindPackagedGuardd()
{
    fs::path executable;
#ifdef _WIN32
    std::vector<wchar_t> text(32768);
    const DWORD length = GetModuleFileNameW(nullptr, text.data(), static_cast<DWORD>(text.size()));
    if (length == 0 || length >= text.size()) return {};
    executable = fs::path(std::wstring(text.data(), length));
#elif defined(__APPLE__)
    uint32_t length=0; _NSGetExecutablePath(nullptr,&length);
    if (length == 0 || length > 65536) return {};
    std::vector<char> text(length);
    if (_NSGetExecutablePath(text.data(),&length) != 0) return {};
    executable=fs::PathFromString(text.data());
#else
    std::vector<char> text(65536);
    const ssize_t length=readlink("/proc/self/exe",text.data(),text.size()-1);
    if (length <= 0) return {};
    executable=fs::PathFromString(std::string(text.data(),length));
#endif
    std::error_code ec;
    const fs::path directory=fs::canonical(executable,ec).parent_path();
    if (ec) return {};
#ifdef _WIN32
    const fs::path candidate=directory / "btx-guardd.exe";
#else
    const fs::path candidate=directory / "btx-guardd";
#endif
    return fs::is_regular_file(candidate,ec) && !ec ? candidate : fs::path{};
}
class GuardSupervisor::Impl {
public:
    mutable std::mutex mutex;
    GuardProcessStatus status;
    fs::path executable;
    fs::path security_directory;
    Clock::time_point next_attempt{};
    Clock::time_point last_ping{};
    Clock::time_point ready_since{};
    unsigned failures{0};
#ifdef _WIN32
    HANDLE process{nullptr}, job{nullptr}, input{nullptr}, output{nullptr};
#else
    pid_t child{-1};
    int input{-1}, output{-1};
#endif
    bool Alive()
    {
#ifdef _WIN32
        return process && WaitForSingleObject(process,0) == WAIT_TIMEOUT;
#else
        if (child <= 0) return false;
        int child_status=0;
        const auto waited=waitpid(child,&child_status,WNOHANG);
        if (waited==0) return true;
        if (waited<0 && errno==EINTR) return true;
        child=-1; return false;
#endif
    }
    void CloseOwned()
    {
#ifdef _WIN32
        CloseHandleOwned(input); // EOF is the graceful stop signal.
        if (process && WaitForSingleObject(process,250)==WAIT_TIMEOUT) {
            TerminateProcess(process,2); WaitForSingleObject(process,1000);
        }
        CloseHandleOwned(output); CloseHandleOwned(process); CloseHandleOwned(job);
#else
        CloseFd(input); // EOF is the graceful stop signal.
        const auto deadline=Clock::now()+std::chrono::milliseconds(250);
        while (Alive() && Clock::now()<deadline) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (Alive()) {
            kill(child,SIGTERM);
            const auto term_deadline=Clock::now()+std::chrono::milliseconds(250);
            while (Alive() && Clock::now()<term_deadline) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (Alive()) {
            kill(child,SIGKILL);
            int child_status=0;
            while(waitpid(child,&child_status,0)<0 && errno==EINTR) {}
            child=-1;
        }
        CloseFd(output);
#endif
        status.ready=false; status.pid=-1;
    }
    void Failed(const char* error)
    {
        CloseOwned(); status.error=error;
        failures=std::min(failures+1,7U);
        next_attempt=Clock::now()+std::chrono::milliseconds(std::min(60000U,500U<<failures));
    }
    bool Transport(const std::string& line, std::string& reply, std::chrono::milliseconds budget=EXCHANGE_TIMEOUT)
    {
        if (line.empty() || line.size()>GuardTable::kMaxLine || line.find_first_of("\r\n\0",0,3)!=std::string::npos) return false;
        const auto deadline=Clock::now()+budget;
        const std::string bytes=line+"\n";
        size_t sent=0; reply.clear();
#ifdef _WIN32
        if (!input || !output) return false;
        DWORD wrote=0;
        // At most one request is outstanding, and the 8192-byte pipe can hold
        // the entire bounded 4097-byte request without waiting on the child.
        if (!WriteFile(input,bytes.data(),static_cast<DWORD>(bytes.size()),&wrote,nullptr) || wrote!=bytes.size()) return false;
        sent=wrote;
#else
        if (input<0 || output<0) return false;
        while (sent<bytes.size()) {
            const auto n=WritePipe(input,bytes.data()+sent,bytes.size()-sent);
            if (n>0) {sent+=n;continue;}
            if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) return false;
            if (Clock::now()>=deadline) return false;
            pollfd fds{input,POLLOUT,0}; poll(&fds,1,10);
        }
#endif
        (void)sent;
        while (Clock::now()<deadline) {
            char buffer[512];
#ifdef _WIN32
            DWORD available=0,got=0;
            if (!PeekNamedPipe(output,nullptr,0,nullptr,&available,nullptr)) return false;
            if (!available) {std::this_thread::sleep_for(std::chrono::milliseconds(5));continue;}
            if (!ReadFile(output,buffer,std::min<DWORD>(sizeof(buffer),available),&got,nullptr)) return false;
            const auto n=static_cast<int>(got);
#else
            pollfd fds{output,POLLIN,0};
            const auto ready=poll(&fds,1,10);
            if (ready<0 && errno!=EINTR) return false;
            if (ready<=0) continue;
            const auto n=read(output,buffer,sizeof(buffer));
            if (n<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
#endif
            if (n<=0 || reply.size()+n>GuardTable::kMaxLine) return false;
            reply.append(buffer,static_cast<size_t>(n));
            const auto newline=reply.find('\n');
            if (newline!=std::string::npos) {
                if (newline!=reply.size()-1 || reply.find('\0')!=std::string::npos) return false;
                reply.pop_back(); return true;
            }
        }
        return false;
    }
    bool Launch()
    {
        std::error_code ec;
        const auto metadata=fs::symlink_status(executable,ec);
        if (executable.empty() || !executable.is_absolute() || ec || !fs::is_regular_file(metadata) || fs::is_symlink(metadata)) {
            Failed("GUARD_EXECUTABLE_ABSENT");return false;
        }
#ifdef _WIN32
        if (!security_directory.empty() &&
            (!security_directory.is_absolute() || security_directory.native().find(L'"') != std::wstring::npos)) {
            Failed("SEC_DIRECTORY"); return false;
        }
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
        HANDLE child_input=nullptr,child_output=nullptr,child_error=nullptr;
        if (!CreatePipe(&child_input,&input,&security,8192) || !CreatePipe(&output,&child_output,&security,8192)) {
            CloseHandleOwned(child_input);CloseHandleOwned(child_output);Failed("GUARD_PIPE");return false;
        }
        SetHandleInformation(input,HANDLE_FLAG_INHERIT,0);SetHandleInformation(output,HANDLE_FLAG_INHERIT,0);
        child_error=CreateFileW(L"NUL",GENERIC_WRITE,FILE_SHARE_WRITE|FILE_SHARE_READ,&security,OPEN_EXISTING,0,nullptr);
        if(child_error==INVALID_HANDLE_VALUE) {CloseHandleOwned(child_input);CloseHandleOwned(child_output);Failed("GUARD_PIPE");return false;}
        STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);
        startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;startup.StartupInfo.hStdInput=child_input;
        startup.StartupInfo.hStdOutput=child_output;startup.StartupInfo.hStdError=child_error;
        SIZE_T needed=0;InitializeProcThreadAttributeList(nullptr,1,0,&needed);
        std::vector<unsigned char> attributes(needed);
        startup.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
        const HANDLE allowed[]{child_input,child_output,child_error};
        const bool initialized=InitializeProcThreadAttributeList(startup.lpAttributeList,1,0,&needed)!=0;
        const bool configured=initialized && UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
             const_cast<HANDLE*>(allowed),sizeof(allowed),nullptr,nullptr)!=0;
        std::wstring command=L"\""+executable.native()+L"\" --stdio";
        if (!security_directory.empty()) {
            std::wstring value = security_directory.native();
            size_t trailing = 0;
            while (trailing < value.size() && value[value.size()-1-trailing] == L'\\') ++trailing;
            // CommandLineToArgvW requires trailing backslashes to be doubled
            // before the closing quote. Never append a filesystem dot component.
            command += L" --security-dir \"" + value + std::wstring(trailing, L'\\') + L"\"";
        }
        wchar_t system_root[32768];const UINT count=GetWindowsDirectoryW(system_root,32768);
        std::wstring environment=L"LANG=C";environment.push_back(0);
        if(count>0 && count<32768) {environment+=L"SystemRoot=";environment.append(system_root,count);environment.push_back(0);}
        environment.push_back(0);
        PROCESS_INFORMATION pi{};
        const bool created=configured && CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,
            EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|CREATE_SUSPENDED,
            environment.data(),executable.parent_path().c_str(),&startup.StartupInfo,&pi)!=0;
        if(initialized)DeleteProcThreadAttributeList(startup.lpAttributeList);
        CloseHandleOwned(child_input);CloseHandleOwned(child_output);CloseHandleOwned(child_error);
        if(!created) {Failed("GUARD_SPAWN");return false;}
        process=pi.hProcess;job=CreateJobObjectW(nullptr,nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit=1;
        if(!job || !SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) ||
           !AssignProcessToJobObject(job,process) || ResumeThread(pi.hThread)==static_cast<DWORD>(-1)) {
            CloseHandle(pi.hThread);Failed("GUARD_JOB");return false;
        }
        CloseHandle(pi.hThread);status.pid=pi.dwProcessId;
#else
        int requests[2]{-1,-1}, responses[2]{-1,-1};
        if(pipe(requests)!=0 || pipe(responses)!=0) {
            for(int& fd:requests)CloseFd(fd);
            for(int& fd:responses)CloseFd(fd);
            Failed("GUARD_PIPE");return false;
        }
        // Keep protocol descriptors above stdio even when the node was
        // launched with one of its own standard descriptors closed.
        for(int* descriptor:{&requests[0],&requests[1],&responses[0],&responses[1]}) {
            if(*descriptor<3) {
                const int moved=fcntl(*descriptor,F_DUPFD_CLOEXEC,3);
                if(moved<0) {
                    for(int& fd:requests)CloseFd(fd);
                    for(int& fd:responses)CloseFd(fd);
                    Failed("GUARD_PIPE");return false;
                }
                close(*descriptor);*descriptor=moved;
            }
        }
        for(int fd:{requests[0],requests[1],responses[0],responses[1]}) {
            if(fcntl(fd,F_SETFD,FD_CLOEXEC)!=0) {
                for(int& item:requests)CloseFd(item);
                for(int& item:responses)CloseFd(item);
                Failed("GUARD_PIPE");return false;
            }
        }
        const long fd_max=std::max(1024L,sysconf(_SC_OPEN_MAX));
        char arg_stdio[]="--stdio", lang[]="LANG=C", path[]="PATH=/usr/bin:/bin";
        char arg_security[]="--security-dir";
        char* const argv[]{const_cast<char*>(executable.c_str()), arg_stdio,
            security_directory.empty() ? nullptr : arg_security,
            security_directory.empty() ? nullptr : const_cast<char*>(security_directory.c_str()), nullptr};
        char* const environment[]{lang,path,nullptr};
#ifdef __linux__
        const pid_t owner=getpid();
#endif
        child=fork();
        if(child<0){
            for(int& fd:requests)CloseFd(fd);
            for(int& fd:responses)CloseFd(fd);
            Failed("GUARD_SPAWN");return false;
        }
        if(child==0){
            close(requests[1]);close(responses[0]);
            if(dup2(requests[0],STDIN_FILENO)<0 || dup2(responses[1],STDOUT_FILENO)<0)_exit(126);
            const int null=open("/dev/null",O_WRONLY);
            if(null<0 || dup2(null,STDERR_FILENO)<0)_exit(126);
#ifdef __linux__
            if(prctl(PR_SET_PDEATHSIG,SIGTERM)!=0 || getppid()!=owner)_exit(126);
#ifdef SYS_close_range
            if(syscall(SYS_close_range,3U,~0U,0U)!=0)
#endif
#endif
            {for(long fd=3;fd<fd_max;++fd)close(static_cast<int>(fd));}
            execve(executable.c_str(),argv,environment);_exit(126);
        }
        close(requests[0]);close(responses[1]);input=requests[1];output=responses[0];
        if(fcntl(input,F_SETFL,fcntl(input,F_GETFL,0)|O_NONBLOCK)<0 ||
           fcntl(output,F_SETFL,fcntl(output,F_GETFL,0)|O_NONBLOCK)<0) {Failed("GUARD_PIPE");return false;}
        status.pid=child;
#endif
        std::string reply;
        // The first reply waits out private-directory and database setup.
        // Later health checks keep the short exchange budget.
        if(!Transport("PING",reply,std::chrono::seconds(5)) || reply!="READY BTX_GUARD/1"){Failed("GUARD_NOT_READY");return false;}
        status.ready=true;status.error.clear();last_ping=Clock::now();ready_since=last_ping;return true;
    }
};
GuardSupervisor::GuardSupervisor():m_impl(std::make_unique<Impl>()){}
GuardSupervisor::~GuardSupervisor(){Stop();}
bool GuardSupervisor::Start(const fs::path& path,std::string& error)
{
    return Start(path, {}, error);
}
bool GuardSupervisor::Start(const fs::path& path,const fs::path& security_directory,std::string& error)
{
    std::lock_guard lock(m_impl->mutex);m_impl->CloseOwned();
    if (!security_directory.empty() && !security_directory.is_absolute()) {
        error="SEC_DIRECTORY"; return false;
    }
    m_impl->security_directory=security_directory;
    m_impl->executable=path.empty()?FindPackagedGuardd():path;
    m_impl->status={};m_impl->status.enabled=true;m_impl->failures=0;
    const bool ok=m_impl->Launch();error=m_impl->status.error;return ok;
}
void GuardSupervisor::Tick()
{
    std::lock_guard lock(m_impl->mutex);if(!m_impl->status.enabled)return;
    if(!m_impl->status.ready){
        if(Clock::now()>=m_impl->next_attempt){++m_impl->status.restart_count;m_impl->Launch();}
        return;
    }
    if(!m_impl->Alive()){m_impl->Failed("GUARD_EXITED");return;}
    if(Clock::now()-m_impl->last_ping<std::chrono::seconds(2))return;
    std::string reply;
    if(!m_impl->Transport("PING",reply) || reply!="READY BTX_GUARD/1"){m_impl->Failed("GUARD_HEALTH");return;}
    m_impl->last_ping=Clock::now();
    if(m_impl->last_ping-m_impl->ready_since>=std::chrono::seconds(30))m_impl->failures=0;
}
void GuardSupervisor::Stop()
{
    if(!m_impl)return;
    std::lock_guard lock(m_impl->mutex);m_impl->status.enabled=false;m_impl->CloseOwned();
}
bool GuardSupervisor::Exchange(const std::string& line,std::string& reply,std::string& error)
{
    std::lock_guard lock(m_impl->mutex);
    if(!m_impl->status.ready){error="GUARD_NOT_READY";return false;}
    if(line.empty() || line.size()>GuardTable::kMaxLine || line.find_first_of("\r\n\0",0,3)!=std::string::npos){error="BTX035_SCHEMA";return false;}
    if(!m_impl->Transport(line,reply)){m_impl->Failed("GUARD_TRANSPORT");error=m_impl->status.error;return false;}
    error.clear();return true;
}
GuardProcessStatus GuardSupervisor::Snapshot()const
{
    std::lock_guard lock(m_impl->mutex);return m_impl->status;
}

bool GuardSupervisor::SecurityExchange(const UniValue& request, UniValue& response, std::string& error)
{
#ifdef BTX_MODEL_SECURITY_V2
    // Hold the lock for the ENTIRE frame sequence: health checks and concurrent
    // RPC requests may not interleave fragments or consume another response.
    std::lock_guard lock(m_impl->mutex);
    if (!m_impl->status.ready || m_impl->security_directory.empty()) {
        error = "SEC_GUARD_NOT_READY";
        return false;
    }
    try {
        using namespace security;
        const auto raw = Canonical(request);
        Require(!raw.empty() && raw.size() <= MAX_RECORD, "SEC_FRAME_LIMIT");
        const auto id = Hex(RandomBytes(16));
        const auto deadline = Clock::now() + std::chrono::seconds(9);
        auto exchange = [&](const std::string& line) {
            Require(Clock::now() < deadline, "SEC_FRAME_TIMEOUT");
            std::string reply;
            Require(m_impl->Transport(line, reply), "SEC_GUARD_TRANSPORT");
            Require(reply.rfind("ERR ", 0) != 0, "SEC_GUARD_REFUSED");
            return reply;
        };
        Require(exchange("SEC2 BEGIN " + id + " " + std::to_string(raw.size())) == "SEC2 READY " + id,
                "SEC_FRAME_RESPONSE");
        for (size_t offset = 0; offset < raw.size();) {
            const size_t count = std::min<size_t>(1536, raw.size() - offset);
            const auto bytes = std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(raw.data() + offset), count);
            const auto reply = exchange("SEC2 DATA " + id + " " + std::to_string(offset) + " " + Hex(bytes));
            offset += count;
            Require(reply == "SEC2 STORED " + std::to_string(offset), "SEC_FRAME_RESPONSE");
        }
        const auto committed = exchange("SEC2 COMMIT " + id);
        const std::string prefix = "SEC2 RESPONSE " + id + " ";
        Require(committed.rfind(prefix, 0) == 0, "SEC_FRAME_RESPONSE");
        const auto size = ParseUInt(std::string_view(committed).substr(prefix.size()));
        Require(size > 0 && size <= MAX_RECORD, "SEC_FRAME_LIMIT");
        std::string output;
        output.reserve(size);
        while (output.size() < size) {
            const auto offset = output.size();
            const auto reply = exchange("SEC2 READ " + id + " " + std::to_string(offset));
            const std::string start = "SEC2 BYTES " + std::to_string(offset) + " ";
            Require(reply.rfind(start, 0) == 0, "SEC_FRAME_RESPONSE");
            const auto part = Unhex(std::string_view(reply).substr(start.size()), 1536);
            Require(!part.empty() && part.size() <= size - offset, "SEC_FRAME_LIMIT");
            output.append(reinterpret_cast<const char*>(part.data()), part.size());
        }
        response = Parse(output);
        error.clear();
        return true;
    } catch (const security::Error& e) {
        error = e.code;
        // A partial protocol exchange must not be reused; restart loses all
        // in-memory output and invalidates outstanding boot-bound permits.
        m_impl->Failed("SEC_GUARD_PROTOCOL");
        return false;
    } catch (...) {
        error = "SEC_GUARD_EXCEPTION";
        m_impl->Failed("SEC_GUARD_PROTOCOL");
        return false;
    }
#else
    (void)request;
    (void)response;
    error = "SEC_V2_NOT_BUILT";
    return false;
#endif
}

} // namespace modelnet
