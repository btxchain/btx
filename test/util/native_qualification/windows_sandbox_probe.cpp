// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
// An actual Windows escape probe, executed only by an explicit owner test.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <fstream>
#include <string>
#include <cstdlib>
#include <charconv>
#include <vector>
namespace {
std::wstring Wide(const std::string& input)
{
    const int size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0);
    if(size<=0)return {};
    std::wstring output(size,0);
    if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),output.data(),size)!=size)return {};
    return output;
}
}
int main()
{
    if(std::getenv("BTX_NATIVE_SECRET_SENTINEL"))return 10;
    std::ifstream config("probe-config.txt");
    std::string witness,port_text;
    if(!std::getline(config,witness) || !std::getline(config,port_text))return 11;
    unsigned port=0;
    const auto parsed=std::from_chars(port_text.data(),port_text.data()+port_text.size(),port);
    if(parsed.ec!=std::errc{} || parsed.ptr!=port_text.data()+port_text.size() || port==0 || port>65535)return 12;
    const auto path=Wide(witness);if(path.empty())return 13;
    HANDLE outside=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    const DWORD access_error=GetLastError();
    if(outside!=INVALID_HANDLE_VALUE){CloseHandle(outside);return 14;}
    if(access_error!=ERROR_ACCESS_DENIED)return 15; // missing file is no evidence
    WSADATA network{};if(WSAStartup(MAKEWORD(2,2),&network)!=0)return 16;
    SOCKET channel=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(channel==INVALID_SOCKET)return 17;
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    address.sin_port=htons(static_cast<unsigned short>(port));
    const int connected=connect(channel,reinterpret_cast<const sockaddr*>(&address),sizeof(address));
    const int network_error=WSAGetLastError();closesocket(channel);WSACleanup();
    // The parent is listening on this exact loopback port. A refusal/timeout
    // is insufficient: Windows must report access denial from the sandbox.
    if(connected==0 || network_error!=WSAEACCES)return 18;
    wchar_t system[32768];const UINT size=GetSystemDirectoryW(system,32768);
    if(size==0 || size>=32768)return 19;
    const std::wstring executable=std::wstring(system,size)+L"\\cmd.exe";
    std::wstring command=L"\""+executable+L"\" /d /c exit 0";
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION child{};
    if(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,
                      nullptr,nullptr,&startup,&child)) {
        TerminateProcess(child.hProcess,2);WaitForSingleObject(child.hProcess,5000);
        CloseHandle(child.hThread);CloseHandle(child.hProcess);return 20;
    }
    std::ofstream output("probe-result.txt",std::ios::binary);
    output<<"filesystem-denied network-denied environment-clean native-executed\n";
    return output.good()?0:21;
}
