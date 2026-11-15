#include <modelnet/erasure_store.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/types.h>
#include <crypto/sha384.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
namespace fs = std::filesystem;
void Check(bool ok,const char* name) {if(!ok)throw std::runtime_error(name);std::cout<<"PASS "<<name<<'\n';}
void Write(const fs::path&p,const std::vector<unsigned char>&b) {std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());if(!f)throw std::runtime_error("fixture write");}
std::vector<unsigned char> Read(const fs::path&p) {std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
std::string Hash(const std::vector<unsigned char>&b) {CSHA384 h;h.Write(b.data(),b.size());modelnet::Digest48 d;h.Finalize(d.data.data());return d.Hex();}
int main(int argc,char**argv) {
 try {
  if(argc!=2)throw std::runtime_error("fresh fixture directory required");
  const fs::path root=fs::absolute(argv[1]);Check(fs::create_directory(root),"fresh fixture");
  std::vector<unsigned char>a(256),b(256);for(int i=0;i<256;++i){a[i]=static_cast<unsigned char>(i);b[i]=static_cast<unsigned char>(255-i);}
  auto expected=a;expected.insert(expected.end(),b.begin(),b.end());Write(root/"a",a);Write(root/"b",b);
  modelnet::ErasureManifest m;m.data_shards=2;m.total_shards=3;m.shard_bytes=256;m.stripe_count=1;m.file_size_bytes=512;m.final_real_piece_count=2;
  modelnet::ErasureStripe stripe;stripe.stripe_index=0;stripe.positions={0,1};stripe.shard_hash_hex={Hash(a),Hash(b)};m.stripes={stripe};
  std::vector<std::string>inputs={(root/"a").string(),(root/"b").string()};std::string err;
  auto repair=[&](const modelnet::ErasureManifest&man,const fs::path&dest,const std::vector<int>&pos=std::vector<int>{0,1}){err.clear();return modelnet::RepairStripeFromFiles(man,inputs,pos,dest.string(),err,0);};
  const auto output=root/"output";
  Check(repair(m,output),"real repair succeeds");Check(Read(output)==expected,"binary bytes preserved");Check(!fs::exists(output.string()+".tmp"),"successful temporary cleanup");
  const bool repeated=repair(m,output);
#ifdef _WIN32
  Check(!repeated&&err=="dest rename","existing Windows destination refused");
#else
  Check(repeated,"existing POSIX destination replaced");
#endif
  Check(Read(output)==expected&&!fs::exists(output.string()+".tmp"),"existing output and temporary state correct");
  auto bad=m;bad.stripes[0].shard_hash_hex[0]=std::string(96,'0');Check(!repair(bad,root/"hash-failure")&&err=="shard hash mismatch","hash refusal");Check(!fs::exists(root/"hash-failure"),"hash refusal leaves no output");
  Check(!repair(m,root/"duplicate",{0,0}),"duplicate position refusal");
  Write(root/"a",{1});Check(!repair(m,root/"short")&&err=="shard size","short shard refusal");Write(root/"a",a);
  fs::remove(root/"a");Check(!repair(m,root/"missing")&&err=="shard open","missing shard refusal");Write(root/"a",a);
  fs::create_directory(root/"blocked.tmp");Check(!repair(m,root/"blocked")&&err=="dest open","exclusive temporary creation refusal");Check(fs::is_directory(root/"blocked.tmp"),"existing directory preserved");
  fs::create_directory(root/"rename-target");Check(!repair(m,root/"rename-target")&&err=="dest rename","rename failure refusal");Check(!fs::exists(root/"rename-target.tmp"),"rename failure temporary cleanup");Check(fs::is_directory(root/"rename-target"),"rename target preserved");
  Check(repair(m,root/"recovery")&&Read(root/"recovery")==expected,"subsequent repair healthy");
  fs::remove_all(root);Check(!fs::exists(root),"all descriptors closed and fixture removed");return 0;
 }catch(const std::exception&e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
