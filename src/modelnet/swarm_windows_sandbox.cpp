// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <objbase.h>
#include <modelnet/swarm_windows_sandbox.h>
#include <modelnet/swarm_process_guard.h>
#include <modelnet/swarm_native_io.h>
#include <array>
#include <map>
#include <limits>
#include <climits>
#include <fstream>
#include <memory>
#include <vector>

namespace modelnet {
namespace {
constexpr size_t MAX_ENTRIES=8192;
constexpr uint64_t MAX_OUTPUT_BYTES=64ULL*1024*1024;
struct Handle {
    HANDLE value{nullptr};
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle()=default;
    explicit Handle(HANDLE object):value(object){}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    explicit operator bool()const{return value && value!=INVALID_HANDLE_VALUE;}
};
struct LocalMemory {
    void* value{nullptr};
    ~LocalMemory(){if(value)LocalFree(value);}
};
std::wstring RandomName()
{
    std::array<unsigned char,16> entropy{};
    if(BCryptGenRandom(nullptr,entropy.data(),static_cast<ULONG>(entropy.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)return {};
    static constexpr wchar_t hex[]=L"0123456789abcdef";
    std::wstring name=L"btx.native.";
    for(unsigned char byte:entropy){name+=hex[byte>>4];name+=hex[byte&15];}
    return name;
}
bool TokenBytes(HANDLE token,TOKEN_INFORMATION_CLASS kind,std::vector<unsigned char>& bytes)
{
    DWORD needed=0;GetTokenInformation(token,kind,nullptr,0,&needed);
    if(needed==0 || needed>1024*1024)return false;
    bytes.resize(needed);
    return GetTokenInformation(token,kind,bytes.data(),needed,&needed)!=0;
}
bool RemovePrivateTree(const fs::path& path,size_t& visited,unsigned depth=0)
{
    if(++visited>100000 || depth>64)return false;
    const DWORD attributes=GetFileAttributesW(path.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES)return GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND;
    if(!(attributes&FILE_ATTRIBUTE_DIRECTORY)) {
        SetFileAttributesW(path.c_str(),FILE_ATTRIBUTE_NORMAL);
        return DeleteFileW(path.c_str())!=0;
    }
    // Never recurse through junctions or any other reparse object produced
    // by the child; deleting the junction itself cannot traverse its target.
    if(attributes&FILE_ATTRIBUTE_REPARSE_POINT)return RemoveDirectoryW(path.c_str())!=0;
    WIN32_FIND_DATAW entry{};
    const HANDLE search=FindFirstFileW((path/fs::path(L"*")).c_str(),&entry);
    if(search==INVALID_HANDLE_VALUE)return false;
    bool ok=true;
    do {
        const std::wstring name=entry.cFileName;
        if(name==L"." || name==L"..")continue;
        if(!RemovePrivateTree(path/fs::path(name),visited,depth+1)){ok=false;break;}
    }while(FindNextFileW(search,&entry));
    if(ok && GetLastError()!=ERROR_NO_MORE_FILES)ok=false;
    FindClose(search);
    return ok && RemoveDirectoryW(path.c_str())!=0;
}
struct Profile {
    std::wstring name;
    PSID sid{nullptr};
    fs::path work;
    PSECURITY_DESCRIPTOR descriptor{nullptr};
    bool created{false};
    ~Profile(){Cleanup();}
    bool Cleanup()
    {
        bool ok=true;
        if(!work.empty()) {
            size_t visited=0;if(!RemovePrivateTree(work,visited))ok=false;
            work.clear();
        }
        if(created){if(FAILED(DeleteAppContainerProfile(name.c_str())))ok=false;created=false;}
        if(sid){FreeSid(sid);sid=nullptr;}
        if(descriptor){LocalFree(descriptor);descriptor=nullptr;}
        return ok;
    }
    bool Create()
    {
        name=RandomName();if(name.empty())return false;
        if(FAILED(CreateAppContainerProfile(name.c_str(),L"BTX native probe",L"Ephemeral owner-requested probe",nullptr,0,&sid)))return false;
        created=true;
        LPWSTR package_text=nullptr;
        if(!ConvertSidToStringSidW(sid,&package_text))return false;
        LocalMemory package{package_text};
        PWSTR folder=nullptr;
        if(FAILED(GetAppContainerFolderPath(package_text,&folder)))return false;
        work=fs::path(folder)/"work";CoTaskMemFree(folder);
        Handle token;
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value))return false;
        std::vector<unsigned char> user;
        if(!TokenBytes(token.value,TokenUser,user))return false;
        LPWSTR user_text=nullptr;
        if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&user_text))return false;
        LocalMemory owner{user_text};
        // Only this user, SYSTEM and this fresh package SID can access work.
        // Low-integrity writes are allowed only inside this temporary tree.
        const std::wstring sddl=L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+std::wstring(user_text)+
            L")(A;OICI;FA;;;"+std::wstring(package_text)+L")S:(ML;OICI;NW;;;LW)";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr))return false;
        SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};
        return CreateDirectoryW(work.c_str(),&security)!=0 && process_guard::NoSymlinkPath(work);
    }
};
struct FileIdentity {uint64_t bytes{0};std::string sha384;};
using Tree=std::map<fs::path,FileIdentity>;
bool FileBytes(const fs::path& path,uint64_t cap,std::vector<unsigned char>& bytes)
{
    Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(!file)return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(file.value,&info) || (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) ||
       info.nNumberOfLinks!=1)return false;
    const uint64_t length=(static_cast<uint64_t>(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    if(length>cap || length>SIZE_MAX)return false;
    bytes.resize(static_cast<size_t>(length));size_t offset=0;
    while(offset<bytes.size()) {
        DWORD got=0;const DWORD wanted=static_cast<DWORD>(std::min<size_t>(bytes.size()-offset,1024*1024));
        if(!ReadFile(file.value,bytes.data()+offset,wanted,&got,nullptr) || got!=wanted)return false;
        offset+=got;
    }
    unsigned char extra;DWORD got=0;
    return ReadFile(file.value,&extra,1,&got,nullptr)!=0 && got==0;
}
bool CreateFileBytes(const fs::path& path,std::span<const unsigned char> bytes)
{
    Handle file(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(!file)return false;
    size_t offset=0;
    while(offset<bytes.size()) {
        DWORD written=0;const DWORD wanted=static_cast<DWORD>(std::min<size_t>(bytes.size()-offset,1024*1024));
        if(!WriteFile(file.value,bytes.data()+offset,wanted,&written,nullptr) || written!=wanted)return false;
        offset+=written;
    }
    return FlushFileBuffers(file.value)!=0;
}
bool Snapshot(const fs::path& root,uint64_t cap,Tree& tree,const fs::path* copy_to=nullptr)
{
    std::error_code ec;uint64_t total=0;size_t entries=0;
    fs::recursive_directory_iterator current(root,fs::directory_options::none,ec),end;
    if(ec)return false;
    for(;current!=end;current.increment(ec)) {
        if(ec || ++entries>MAX_ENTRIES || current.depth()>64)return false;
        const auto& path=current->path();
        if(!process_guard::NoSymlinkPath(path))return false;
        const fs::path relative=path.lexically_relative(root);
        if(current->is_directory(ec)) {
            if(copy_to && !CreateDirectoryW((*copy_to/relative).c_str(),nullptr))return false;
            continue;
        }
        if(ec || !current->is_regular_file(ec) || ec)return false;
        std::vector<unsigned char> bytes;
        if(!FileBytes(path,cap-total,bytes))return false;
        total+=bytes.size();
        tree.emplace(relative,FileIdentity{bytes.size(),native_io::Digest(bytes)});
        if(copy_to && !CreateFileBytes(*copy_to/relative,bytes))return false;
    }
    return !ec;
}
bool PublishOutputs(const fs::path& original,const fs::path& staged,const Tree& before,uint64_t cap)
{
    Tree after;
    if(cap>std::numeric_limits<uint64_t>::max()-MAX_OUTPUT_BYTES || !Snapshot(staged,cap+MAX_OUTPUT_BYTES,after))return false;
    for(const auto& [path,identity]:before) {
        const auto it=after.find(path);
        if(it==after.end() || identity.bytes!=it->second.bytes || identity.sha384!=it->second.sha384)return false;
    }
    uint64_t total=0;
    for(const auto& [relative,identity]:after) {
        if(before.count(relative))continue;
        if(identity.bytes>MAX_OUTPUT_BYTES-total)return false;
        total+=identity.bytes;
        const fs::path target=original/relative;
        // Create one directory component at a time and reject all reparse
        // points; child-provided names can never escape the owner work root.
        fs::path directory=original;
        for(const auto& component:relative.parent_path()) {
            if(component==L".." || component==L"." || component.empty())return false;
            directory/=component;
            std::error_code ec;
            if(!std::filesystem::exists(directory,ec) && !CreateDirectoryW(directory.c_str(),nullptr))return false;
            if(ec || !process_guard::NoSymlinkPath(directory) || !fs::is_directory(directory,ec) || ec)return false;
        }
        std::vector<unsigned char> bytes;
        if(!FileBytes(staged/relative,identity.bytes,bytes) || native_io::Digest(bytes)!=identity.sha384 ||
           !CreateFileBytes(target,bytes))return false;
    }
    return true;
}
bool VerifyAppContainer(HANDLE process,PSID expected)
{
    Handle token;
    if(!OpenProcessToken(process,TOKEN_QUERY,&token.value))return false;
    DWORD is_container=0,received=0;
    if(!GetTokenInformation(token.value,TokenIsAppContainer,&is_container,sizeof(is_container),&received) || !is_container)return false;
    std::vector<unsigned char> package,capabilities,integrity;
    if(!TokenBytes(token.value,TokenAppContainerSid,package) || !TokenBytes(token.value,TokenCapabilities,capabilities) ||
       !TokenBytes(token.value,TokenIntegrityLevel,integrity))return false;
    const auto* app=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(package.data());
    if(!app->TokenAppContainer || !EqualSid(app->TokenAppContainer,expected) ||
       reinterpret_cast<TOKEN_GROUPS*>(capabilities.data())->GroupCount!=0)return false;
    PSID label=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid;
    if(!IsValidSid(label) || *GetSidSubAuthorityCount(label)==0)return false;
    return *GetSidSubAuthority(label,*GetSidSubAuthorityCount(label)-1)<=SECURITY_MANDATORY_LOW_RID;
}
SwarmConfineResult Fail(const char* code,std::string& error)
{
    SwarmConfineResult result;result.code=code;error=code;return result;
}
}
bool WindowsOwnerOnlyFile(const fs::path& path)
{
    if(!process_guard::NoSymlinkPath(path))return false;
    Handle file(CreateFileW(path.c_str(),READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    Handle token;
    if(!file || !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value))return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(file.value,&info) || info.nNumberOfLinks!=1 ||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)))return false;
    std::vector<unsigned char> user;
    if(!TokenBytes(token.value,TokenUser,user))return false;
    const PSID self=reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(GetSecurityInfo(file.value,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&descriptor)!=ERROR_SUCCESS)return false;
    LocalMemory security{descriptor};
    if(!owner || !EqualSid(owner,self) || !acl)return false;
    std::array<unsigned char,SECURITY_MAX_SID_SIZE> system{};DWORD length=system.size();
    if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system.data(),&length))return false;
    bool owner_allowed=false;
    for(DWORD index=0;index<acl->AceCount;++index) {
        void* raw=nullptr;if(!GetAce(acl,index,&raw))return false;
        const auto* header=static_cast<ACE_HEADER*>(raw);
        if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE)return false;
        const auto* allowed=static_cast<ACCESS_ALLOWED_ACE*>(raw);
        PSID subject=const_cast<DWORD*>(&allowed->SidStart);
        if(EqualSid(subject,self))owner_allowed=true;
        else if(!EqualSid(subject,system.data()))return false;
    }
    return owner_allowed;
}
bool WriteWindowsReleaseExclusive(const fs::path& path,const std::string& body,std::string& error)
{
    if(!path.is_absolute() || path.filename().empty() || !process_guard::NoSymlinkPath(path.parent_path())) {
        error="RELEASE_PATH";return false;
    }
    Handle token;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value)){error="RELEASE_OWNER";return false;}
    std::vector<unsigned char> user;
    if(!TokenBytes(token.value,TokenUser,user)){error="RELEASE_OWNER";return false;}
    LPWSTR text=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&text)){error="RELEASE_OWNER";return false;}
    LocalMemory owner{text};
    const std::wstring sddl=L"D:P(A;;FA;;;"+std::wstring(text)+L")(A;;FA;;;SY)";
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) {
        error="RELEASE_SECURITY";return false;
    }
    LocalMemory security{descriptor};
    const std::wstring random=RandomName();
    if(random.empty()){error="RELEASE_RANDOM";return false;}
    const fs::path temporary=path.parent_path()/fs::path(L"."+random+L".release");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    HANDLE file=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,&attributes,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(file==INVALID_HANDLE_VALUE){error="RELEASE_CREATE";return false;}
    bool ok=true;size_t offset=0;
    while(offset<body.size()) {
        DWORD written=0;const DWORD wanted=static_cast<DWORD>(std::min<size_t>(body.size()-offset,1024*1024));
        if(!WriteFile(file,body.data()+offset,wanted,&written,nullptr) || written!=wanted){ok=false;break;}
        offset+=written;
    }
    if(ok && !FlushFileBuffers(file))ok=false;
    if(!CloseHandle(file))ok=false;
    // Same-directory rename is atomic; omitting REPLACE_EXISTING makes an
    // existing release or link a failure, never an overwrite.
    if(ok && !MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH))ok=false;
    if(!ok){DeleteFileW(temporary.c_str());error="RELEASE_WRITE_OR_EXISTS";return false;}
    error.clear();return true;
}
SwarmConfineResult SwarmRunWindowsAppContainer(const SwarmConfineRequest& request,std::string& error)
{
    // AppContainer capabilities, not a caller label or a restricted-token
    // approximation, enforce network and private user-file denial.
    if(!request.network_denied || !process_guard::InsideRoot(request.helper,request.root) ||
       request.max_address_bytes<=0 || request.max_cpu_seconds<=0 || request.max_cpu_seconds>86400 ||
       request.max_wall_seconds<=0 || request.max_wall_seconds>86400 || request.max_tree_bytes==0 ||
       static_cast<uint64_t>(request.max_address_bytes)>SIZE_MAX)return Fail("WINDOWS_SANDBOX_POLICY",error);
    Profile profile;
    if(!profile.Create())return Fail("WINDOWS_APPCONTAINER_CREATE",error);
    Tree inputs;
    if(!Snapshot(request.root,request.max_tree_bytes,inputs,&profile.work))return Fail("WINDOWS_SANDBOX_INPUT",error);
    const fs::path executable=profile.work/fs::path(request.helper.lexically_relative(request.root));
    Handle job(CreateJobObjectW(nullptr,nullptr));
    if(!job)return Fail("WINDOWS_SANDBOX_JOB",error);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|
        JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_PROCESS_TIME|JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit=1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart=static_cast<LONGLONG>(request.max_cpu_seconds)*10000000;
    limits.ProcessMemoryLimit=static_cast<SIZE_T>(request.max_address_bytes);
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    ui.UIRestrictionsClass=JOB_OBJECT_UILIMIT_DESKTOP|JOB_OBJECT_UILIMIT_DISPLAYSETTINGS|JOB_OBJECT_UILIMIT_EXITWINDOWS|
        JOB_OBJECT_UILIMIT_GLOBALATOMS|JOB_OBJECT_UILIMIT_HANDLES|JOB_OBJECT_UILIMIT_READCLIPBOARD|
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS|JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    if(!SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) ||
       !SetInformationJobObject(job.value,JobObjectBasicUIRestrictions,&ui,sizeof(ui)))return Fail("WINDOWS_SANDBOX_JOB",error);
    SECURITY_ATTRIBUTES inherited{sizeof(inherited),nullptr,TRUE};
    Handle null_input(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherited,OPEN_EXISTING,0,nullptr));
    Handle null_output(CreateFileW(L"NUL",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherited,OPEN_EXISTING,0,nullptr));
    if(!null_input || !null_output)return Fail("WINDOWS_SANDBOX_HANDLES",error);
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=null_input.value;
    startup.StartupInfo.hStdOutput=startup.StartupInfo.hStdError=null_output.value;
    SIZE_T needed=0;InitializeProcThreadAttributeList(nullptr,2,0,&needed);
    if(needed==0 || needed>1024*1024)return Fail("WINDOWS_SANDBOX_ATTRIBUTES",error);
    std::vector<unsigned char> attribute_bytes(needed);
    startup.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_bytes.data());
    if(!InitializeProcThreadAttributeList(startup.lpAttributeList,2,0,&needed))return Fail("WINDOWS_SANDBOX_ATTRIBUTES",error);
    SECURITY_CAPABILITIES capabilities{};capabilities.AppContainerSid=profile.sid;
    HANDLE allowed[]{null_input.value,null_output.value};
    const bool attributes=UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &capabilities,sizeof(capabilities),nullptr,nullptr)!=0 &&
        UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,allowed,sizeof(allowed),nullptr,nullptr)!=0;
    wchar_t system[32768];const UINT system_length=GetWindowsDirectoryW(system,32768);
    std::wstring environment;
    auto add=[&](const std::wstring& item){environment+=item;environment.push_back(0);};
    add(L"HF_HUB_OFFLINE=1");add(L"LANG=C");
    if(system_length>0 && system_length<32768)add(L"SystemRoot="+std::wstring(system,system_length));
    add(L"TEMP="+profile.work.native());add(L"TMP="+profile.work.native());environment.push_back(0);
    std::wstring command=L"\""+executable.native()+L"\"";
    PROCESS_INFORMATION created{};
    const bool launched=attributes && CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,
        CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,
        environment.data(),profile.work.c_str(),&startup.StartupInfo,&created)!=0;
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    if(!launched)return Fail("WINDOWS_SANDBOX_CREATEPROCESS",error);
    Handle process(created.hProcess),thread(created.hThread);
    if(!AssignProcessToJobObject(job.value,process.value) || !VerifyAppContainer(process.value,profile.sid)) {
        TerminateProcess(process.value,126);WaitForSingleObject(process.value,5000);
        return Fail("WINDOWS_SANDBOX_TOKEN_OR_JOB",error);
    }
    if(ResumeThread(thread.value)==static_cast<DWORD>(-1)) {
        TerminateJobObject(job.value,126);WaitForSingleObject(process.value,5000);
        return Fail("WINDOWS_SANDBOX_RESUME",error);
    }
    const DWORD waited=WaitForSingleObject(process.value,static_cast<DWORD>(request.max_wall_seconds)*1000);
    if(waited!=WAIT_OBJECT_0) {
        TerminateJobObject(job.value,124);WaitForSingleObject(process.value,5000);
        return Fail(waited==WAIT_TIMEOUT?"CONFINEMENT_TIMEOUT":"WINDOWS_SANDBOX_WAIT",error);
    }
    DWORD exit_code=0;
    if(!GetExitCodeProcess(process.value,&exit_code) || exit_code>INT_MAX)return Fail("WINDOWS_SANDBOX_EXIT",error);
    if(exit_code==0 && !PublishOutputs(request.root,profile.work,inputs,request.max_tree_bytes))return Fail("WINDOWS_SANDBOX_OUTPUT",error);
    if(!profile.Cleanup())return Fail("WINDOWS_SANDBOX_CLEANUP",error);
    SwarmConfineResult result;result.launched=true;result.limits_applied=true;
    result.child_status=static_cast<int>(exit_code);result.code="CONFINED";error.clear();return result;
}
}
#endif // _WIN32
