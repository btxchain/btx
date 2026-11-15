// Copyright (c) 2026 The BTX developers. MIT license.
// Administrative tool. Signing a statement does not prove it is true. Model
// execution and evaluation receipts are emitted by the protected service.
#include <modelnet/security_v2/service.h>
#include <iostream>
#include <map>
namespace {
    using namespace modelnet::security;
    std::map<std::string,std::string> Arguments(int argc,char** argv) {
        std::map<std::string,std::string> out;
        for(int i=2; i<argc; i+=2) {
            Require(i+1<argc&&std::string(argv[i]).starts_with("--"),"SEC_CLI_ARGUMENT");
            Require(out.emplace(argv[i],argv[i+1]).second,"SEC_CLI_DUPLICATE_ARGUMENT");
        }
        return out;
    }
    std::string Arg(const std::map<std::string,std::string>& args,const std::string& key) {
        auto it=args.find(key);
        Require(it!=args.end(),"SEC_CLI_MISSING_ARGUMENT");
        return it->second;
    }
    void Only(const std::map<std::string,std::string>& args,std::initializer_list<std::string_view> names) {
        for(const auto& [name,value]:args) {
            (void)value;
            bool allowed=false;
            for(const auto key:names)allowed|=name==key;
            Require(allowed,"SEC_CLI_UNKNOWN_ARGUMENT");
        }
    }
    KeyPair ReadKey(const std::map<std::string,std::string>& args) {
        auto secret=ReadFile(NativePath(Arg(args,"--secret-file")),SK_BYTES*2+1,true);
        if(!secret.empty()&&secret.back()=='\n')secret.pop_back();
        auto pub=ReadFile(NativePath(Arg(args,"--public-file")),PK_BYTES*2+1);
        if(!pub.empty()&&pub.back()=='\n')pub.pop_back();
        KeyPair key {
            Unhex(pub,PK_BYTES),Unhex(secret,SK_BYTES)
        };
        volatile char* erase=secret.data();
        for(size_t i=0; i<secret.size(); ++i)erase[i]=0;
        Require(key.public_key.size()==PK_BYTES&&key.secret_key.size()==SK_BYTES,"SEC_KEY_SIZE");
        return key;
    }
    void Help() {
        std::cerr<<"BTX model security administrative CLI\n"
        "  keygen --secret-file ABS --public-file ABS\n"
        "  sign --kind KIND --body ABS --secret-file ABS --public-file ABS --output ABS\n"
        "  endorse --record ABS --secret-file ABS --public-file ABS --output ABS\n"
        "  verify --record ABS\n"
        "  init --root ABS --pins ABS\n"
        "  install-policy --root ABS --record ABS\n"
        "  import --root ABS --record ABS\n"
        "  configure --root ABS --local ABS\n"
        "  inspect --root ABS\n"
        "  request --root ABS --request ABS  (offline diagnostic; guard must be stopped)\n"
        "On a running node use btx-cli modelsecurity '{\"op\":\"status\"}'.\n";
    }
}
int main(int argc,char** argv) {
    using namespace modelnet::security;
    try {
        if(argc<2) {
            Help();
            return 1;
        }
        const std::string command=argv[1];
        const auto args=Arguments(argc,argv);
        Json out=Object();
        if(command=="keygen") {
            Only(args, {
                "--secret-file","--public-file"
            });
            auto key=GenerateKey();
            WritePrivate(NativePath(Arg(args,"--secret-file")),Hex(key.secret_key)+"\n");
            WritePrivate(NativePath(Arg(args,"--public-file")),Hex(key.public_key)+"\n");
            out.pushKV("key_id",KeyId(key.public_key));
            out.pushKV("algorithm","ML-DSA-44");
            out.pushKV("wallet_key",false);
        }
        else if(command=="sign"||command=="endorse") {
            Only(args, {
                "--kind","--body","--record","--secret-file","--public-file","--output"
            });
            auto key=ReadKey(args);
            Json record;
            if(command=="sign")record=Envelope(Arg(args,"--kind"),Parse(ReadFile(NativePath(Arg(args,"--body")))));
            else record=Parse(ReadFile(NativePath(Arg(args,"--record"))));
            ValidateEnvelope(record);
            for(const auto& signature:record["signatures"].getValues())
            Require(Verify(Text(record,"kind"),record["body"],Unhex(Text(signature,"public_key",PK_BYTES*2),
            PK_BYTES),
            Unhex(Text(signature,"signature",SIG_BYTES*2),SIG_BYTES)),"SEC_SIGNATURE");
            AddSignature(record,key);
            const auto& last=record["signatures"].getValues().back();
            Require(Verify(Text(record,"kind"),record["body"],key.public_key,Unhex(Text(last,"signature",
            SIG_BYTES*2),SIG_BYTES)),
            "SEC_SIGNING_KEY_MISMATCH");
            WritePrivate(NativePath(Arg(args,"--output")),Canonical(record)+"\n");
            out.pushKV("id",RecordId(record));
            out.pushKV("scope","SIGNED_STATEMENT_ONLY_NOT_EXECUTION_EVIDENCE");
        }
        else if(command=="verify") {
            Only(args, {
                "--record"
            });
            auto e=Parse(ReadFile(NativePath(Arg(args,"--record"))));
            ValidateEnvelope(e);
            Require(e["signatures"].size()>0,"SEC_NO_SIGNATURES");
            for(const auto& s:e["signatures"].getValues())Require(Verify(Text(e,"kind"),e["body"],Unhex(Text(s,
            "public_key",PK_BYTES*2),PK_BYTES),Unhex(Text(s,"signature",SIG_BYTES*2),SIG_BYTES)),"SEC_SIGNATURE");
            out.pushKV("id",RecordId(e));
            out.pushKV("signatures_valid",true);
            out.pushKV("authorized",false);
            out.pushKV("scope","CRYPTOGRAPHIC_INTEGRITY_ONLY");
        }
        else if(command=="init") {
            Only(args, {
                "--root","--pins"
            });
            const auto root=NativePath(Arg(args,"--root"));
            EnsurePrivateDirectory(root);
            auto pins=Parse(ReadFile(NativePath(Arg(args,"--pins"))));
            Fields(pins, {
                "schema","keys","threshold"
            });
            Require(Text(pins,"schema")=="BTX/SecurityRootPins/v1","SEC_ROOT_VERSION");
            auto keys=StringArray(pins["keys"],16);
            for(const auto& key:keys)Require(IsHash(key),"SEC_ROOT_PIN");
            Require(UInt(pins,"threshold",16)>0&&UInt(pins,"threshold",16)<=keys.size(),"SEC_ROOT_THRESHOLD");
            WritePrivate(root/"root-pins.json",Canonical(pins)+"\n");
            Database db(root);
            out.pushKV("automatic_spend_atoms","0");
            out.pushKV("policy_installed",false);
            out.pushKV("compute_granted",false);
        }
        else if(command=="configure") {
            Only(args, {
                "--root","--local"
            });
            const auto root=NativePath(Arg(args,"--root"));
            EnsurePrivateDirectory(root);
            auto local=Parse(ReadFile(NativePath(Arg(args,"--local")),MAX_RECORD,true));
            Require(Text(local,"schema")=="BTX/SecurityLocal/v1","SEC_LOCAL_VERSION");
            WritePrivate(root/"local.json",Canonical(local)+"\n",true);
            Database db(root);
            (void)ReadLocalConfig(db);
            out.pushKV("configured",true);
        }
        else if(command=="install-policy"||command=="import") {
            Only(args, {
                "--root","--record"
            });
            Database db(NativePath(Arg(args,"--root")));
            auto record=Parse(ReadFile(NativePath(Arg(args,"--record"))));
            const auto now=NowMs();
            if(command=="install-policy")InstallPolicy(db,record,now);
            else ImportRecord(db,Policy::Load(db,now),record,now);
            out.pushKV("id",RecordId(record));
        }
        else if(command=="inspect") {
            Only(args, {
                "--root"
            });
            Database db(NativePath(Arg(args,"--root")));
            out.pushKV("policy",db.Meta("active_policy"));
            out.pushKV("journal_valid",db.VerifyJournal());
            out.pushKV("channels",Lifecycle(db).Status());
            out.pushKV("automatic_spend_atoms","0");
        }
        else if(command=="request") {
            Only(args, {
                "--root","--request"
            });
            Service service(NativePath(Arg(args,"--root")));
            out=service.Handle(Parse(ReadFile(NativePath(Arg(args,"--request")))));
            if(out["job"].isStr()) {
                const auto job=out["job"].get_str();
                auto poll=Object();
                poll.pushKV("op","take");
                poll.pushKV("job",job);
                for(size_t i=0; i<61000; ++i) {
                    auto result=service.Handle(poll);
                    if(!result["phase"].isStr()||result["phase"].get_str()=="finished") {
                        out=result;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
        }
        else {
            Help();
            return 1;
        }
        if(!out.exists("ok"))out.pushKV("ok",true);
        std::cout<<Canonical(out)<<'\n';
        return out["ok"].isBool()&&out["ok"].get_bool()?0:2;
    }
    catch(const Error& e) {
        std::cout<<Canonical(Failure(e.code))<<'\n';
        return 2;
    }
    catch(const std::exception&) {
        std::cout<<Canonical(Failure("SEC_CLI_FAILED"))<<'\n';
        return 2;
    }
}
