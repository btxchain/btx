// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#include <modelnet/swarm_windows_sandbox.h>
#include <fstream>
#include <iostream>
#include <iterator>
int main(int argc,char** argv)
{
#ifdef _WIN32
    if(argc!=2)return 1;
    const fs::path root=fs::canonical(fs::PathFromString(argv[1]));
    const fs::path output=root/"exclusive-release-test.json";
    const std::string original="{\"primitive_test_only\":true}\n";
    std::string error;
    if(!modelnet::WriteWindowsReleaseExclusive(output,original,error)){std::cerr<<error;return 2;}
    if(!modelnet::WindowsOwnerOnlyFile(output))return 3;
    if(modelnet::WriteWindowsReleaseExclusive(output,"replaced",error))return 4;
    std::ifstream input(output,std::ios::binary);
    const std::string actual((std::istreambuf_iterator<char>(input)),{});
    if(actual!=original)return 5;
    std::cout<<"{\"windows_release_file_checks\":4,\"model_release_issued\":false}\n";
    return 0;
#else
    (void)argc;(void)argv;return 77;
#endif
}
