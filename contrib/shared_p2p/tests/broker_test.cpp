#include <shared_p2p/runtime.h>
#include <cassert>
#include <iostream>
#ifndef _WIN32
#include <sys/wait.h>
int main(){using namespace btx::p2p;char name[]="/tmp/btx-core-XXXXXX";char* directory=::mkdtemp(name);assert(directory);
 Core core;core.Start(std::string(64,'b'),directory);std::string socket=std::string(directory)+"/control.sock";
 Broker broker(core);broker.Start(socket,std::string(64,'c'));
 pid_t child=::fork();assert(child>=0);
 if(child==0){Client client;client.Configure(socket,std::string(64,'c'));
  auto denied=client.Call({"open","pin","group","CLASSICAL"});if(denied.empty()||denied[0]!="ERROR")_exit(11);
  auto admitted=client.Call({"open","pin","group","PQ1/TLS1.3/MLKEM768/MLDSA44"});if(admitted.size()!=2||admitted[0]!="OK")_exit(12);
  auto charged=client.Call({"charge",admitted[1],"8192","in"});if(charged.empty()||charged[0]!="OK")_exit(13);
  auto wallet=client.Call({"wallet","sendall"});if(wallet.empty()||wallet[0]!="ERROR")_exit(14);
  client.Call({"close",admitted[1]});_exit(0);
 }
 int status=0;::waitpid(child,&status,0);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
 assert(core.Status(Service::ModelNet).ingress_bytes==8192);assert(core.Status(Service::SwapNet).ingress_bytes==0);
 Client bad;bad.Configure(socket,std::string(64,'d'));assert(bad.Call({"status"})[0]=="ERROR");
 broker.Stop();std::filesystem::remove_all(directory);std::cout<<"real child-process broker authority, credential and service checks passed\n";
}
#else
int main(){std::cerr<<"NOT_RUN: upstream supervised ModelNet IPC unsupported on Windows\n";return 77;}
#endif
