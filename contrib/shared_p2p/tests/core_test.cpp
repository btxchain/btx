#include <shared_p2p/core.h>
#include <cassert>
#include <iostream>
int main(){using namespace btx::p2p;Core c;c.Start(std::string(64,'a'));
 assert(c.Admit(Service::ModelNet,"key","group","CLASSICAL").empty());
 auto s=c.Admit(Service::SwapNet,"peer","group","BTX_VERSION_HANDSHAKE");assert(!s.empty());
 assert(!c.Charge(Service::ModelNet,s,1,true));assert(c.Charge(Service::SwapNet,s,100,true));
 auto m=c.Admit(Service::ModelNet,"pin","group","PQ1/TLS1.3/MLKEM768/MLDSA44");assert(!m.empty());
 assert(c.Charge(Service::ModelNet,m,4096,false));assert(c.Status(Service::ModelNet).ingress_bytes==4096);
 assert(c.PublishVerified(Service::SwapNet,{"offer","signed-payload",1,200},100));
 assert(!c.PublishVerified(Service::SwapNet,{"offer","conflict",1,200},100));
 assert(c.PublishVerified(Service::SwapNet,{"offer","revision",2,200},100));
 assert(c.Page(Service::ModelNet,"",10,100).empty());assert(c.Page(Service::SwapNet,"",10,100).size()==1);
 assert(c.Page(Service::SwapNet,"",10,201).empty());c.Close(Service::SwapNet,s);assert(!c.Charge(Service::SwapNet,s,1,true));
 std::cout<<"shared-core service isolation, replay, budgets and expiry passed\n";
}
