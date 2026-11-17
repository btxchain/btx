#include <modelnet/package_execute.h>
#include <modelnet/admission_routes.h>
#include <fstream>
#include <iostream>
#include <sys/resource.h>
#include <signal.h>
#include <filesystem>
#include <cstdlib>
// No resource IDs in this supported local-only plan. Trap if admission unexpectedly executes.
namespace modelnet { bool LivePathAllowed(const std::string&,bool,std::string&){std::abort();} }
std::string Read(const std::string&p){std::ifstream f(p,std::ios::binary);return {(std::istreambuf_iterator<char>(f)),{}};}
void Put(const std::string&p,const std::string&b){std::ofstream f(p,std::ios::binary);f<<b;}
int main(int argc,char**argv){
 namespace fs=std::filesystem;const fs::path root=argv[1];fs::create_directories(root/"out");
 const std::string dest=(root/"out/weights.gguf").string(),source=(root/"source").string(),old="operator-original",good="verified-replacement";
 Put(source,good);std::string digest,err; if(!modelnet::Sha384Path(source,digest,err))return 1;
 modelnet::CreditBroker credit(1024);modelnet::ExecuteAcquisitionRequest req;req.plan.destination=(root/"out").string();req.plan.plan_id_hex=std::string(64,'1');req.files.push_back({"weights.gguf",digest,source});req.stored_digests.push_back({"weights.gguf",digest});req.credit=&credit;
 auto call=[&](const char*label,bool expected,const std::string&codeExpected){modelnet::AcquisitionReceipt out;uint64_t reserved=0;std::string code,err;bool ok=modelnet::ExecuteBtxAcquisition(req,out,reserved,code,err);bool exact=Read(dest)==good;bool pass=ok==expected&&code==codeExpected&&(ok?(exact&&out.ready_state=="MODEL_READY"):(reserved==0&&credit.Reserved()==0&&out.ready_state.empty()));if(ok)credit.Release(reserved);std::cout<<label<<" ok="<<ok<<" code="<<code<<" exists="<<fs::exists(dest)<<" exact="<<exact<<" old="<<(Read(dest)==old)<<" credits="<<credit.Reserved()<<" pass="<<pass<<std::endl;if(!pass)std::exit(3);};
 Put(dest,old);call("valid_replacement",true,"");
 Put(dest,old);req.files[0].source_path.clear();call("missing_source",false,"MODEL_BYTES_UNVERIFIED");if(Read(dest)!=old)return 4;req.files[0].source_path=source;
 Put(source,"wrong-source");call("digest_refusal",false,"MODEL_BYTES_UNVERIFIED");if(Read(dest)!=old)return 5;Put(source,good);
 struct rlimit saved{},limited{};getrlimit(RLIMIT_FSIZE,&saved);limited=saved;limited.rlim_cur=4;signal(SIGXFSZ,SIG_IGN);if(setrlimit(RLIMIT_FSIZE,&limited))return 6;
 call("short_write",false,"IO_ERROR");const bool preserved=Read(dest)==old; if(!preserved)std::cerr<<"FAIL previous destination not preserved after failed replacement"<<std::endl;
 if(setrlimit(RLIMIT_FSIZE,&saved))return 8;
 call("retry_after_short_write",true,"");call("matching_cache_retry",true,"");
 for(const auto& entry:fs::directory_iterator(root/"out"))if(entry.path().filename().string().find(".btx-acq-")==0)return 9;
 fs::remove(dest);call("fresh_destination",true,"");
 fs::remove(dest);fs::create_symlink(source,dest);call("symlink_refusal",false,"SYMLINK_REFUSED");if(Read(source)!=good||!fs::is_symlink(dest))return 10;
 fs::remove_all(root);return preserved?0:7;
}
