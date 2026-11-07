// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#include <modelnet/guard_supervisor.h>
#include <modelnet/guard_machine.h>
#include <chrono>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <limits>
#include <fstream>
#include <cstdlib>
#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
extern char** environ;
#endif
namespace {
unsigned checks=0;
void Check(bool ok,const char* what){if(!ok)throw std::runtime_error(what);++checks;}
}
int main(int argc,char** argv)
{
    try {
#ifndef _WIN32
        // Run this very executable through the real supervisor to check the
        // spawn boundary internally; /proc/environ can be blocked by ptrace
        // restrictions even for the direct parent in hardened CI containers.
        if(argc==2 && std::string(argv[1])=="--stdio") {
            size_t count=0;
            for(char** value=environ;*value;++value) {
                const std::string item=*value;
                if(item!="LANG=C" && item!="PATH=/usr/bin:/bin")return 11;
                ++count;
            }
            if(count!=2)return 12;
            const long maximum=sysconf(_SC_OPEN_MAX);
            for(int fd=3;fd<maximum;++fd)if(fcntl(fd,F_GETFD)>=0)return 13;
            std::string line;
            while(std::getline(std::cin,line)) {
                if(line!="PING")return 14;
                std::cout<<"READY BTX_GUARD/1\n"<<std::flush;
            }
            return 0;
        }
#endif
        Check(argc==2,"guard executable argument");
#ifndef _WIN32
        setenv("BTX_GUARD_PRIVATE_SENTINEL","never-inherit",1);
#endif
        modelnet::GuardSupervisor guard;
        std::string error,reply;
        if (!guard.Start(fs::canonical(fs::PathFromString(argv[1])),error)) throw std::runtime_error("real guard process startup: "+error);
        ++checks;
        auto status=guard.Snapshot();
        Check(status.enabled && status.ready && status.pid>0,"guard reports owned live PID");

        Check(guard.Exchange("PING",reply,error) && reply=="READY BTX_GUARD/1","real private IPC PING");
        Check(guard.Exchange("PREPARE research.run fingerprint 1",reply,error),"prepare through child process");
        std::string verb,secret,commitment;int64_t expires=0;
        std::istringstream parsed(reply);parsed>>verb>>secret>>commitment>>expires;
        Check(verb=="PERMIT" && secret.size()==64 && commitment==modelnet::GuardCommitment(secret),"native bearer commitment");
        Check(guard.Exchange("CONSUME "+secret,reply,error) && reply.ends_with(" PERMIT_CONSUMED NOT_DISPATCHED"),"honest permit consumption");
        Check(guard.Exchange("CONSUME "+secret,reply,error) && reply=="ERR BTX035_REPLAY","one-use replay through process");
        Check(guard.Exchange("PREPARE research.run fingerprint 2",reply,error),"second prepare");
        std::istringstream next(reply);next>>verb>>secret>>commitment>>expires;
        Check(guard.Exchange("PAUSE",reply,error) && reply=="OK","pause child");
        Check(guard.Exchange("RESUME",reply,error) && reply=="OK","resume child");
        Check(guard.Exchange("CONSUME "+secret,reply,error) && reply=="ERR BTX035_REVOKED","resume cannot revive old permit");
        Check(guard.Exchange("PREPARE research.run fp -1",reply,error) && reply=="ERR BTX035_SCHEMA","negative generation rejected");
        Check(guard.Exchange("PING extra",reply,error) && reply=="ERR BTX035_SCHEMA","extra fields rejected");
        Check(!guard.Exchange(std::string(4097,'x'),reply,error) && error=="BTX035_SCHEMA","bounded IPC request");
#ifndef _WIN32
        const auto original=status.pid;
        Check(kill(static_cast<pid_t>(original),SIGKILL)==0,"test kills only owned child");
        const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        do {std::this_thread::sleep_for(std::chrono::milliseconds(20));guard.Tick();status=guard.Snapshot();}
        while((!status.ready || status.pid==original) && std::chrono::steady_clock::now()<end);
        Check(status.ready && status.pid!=original && status.restart_count>=1,"supervisor reaps and restarts with backoff");
        Check(guard.Exchange("CONSUME "+secret,reply,error) && reply=="ERR BTX035_PERMIT","restart never recreates old bearer");
#endif
        guard.Stop();status=guard.Snapshot();
        Check(!status.enabled && !status.ready && status.pid==-1,"EOF stop/reap");
        Check(!guard.Exchange("PING",reply,error),"stopped supervisor refuses requests");
#ifndef _WIN32
        Check(guard.Start(fs::canonical(fs::PathFromString(argv[0])),error),"native spawn boundary inherits only two allowlisted environment entries and three stdio descriptors");
        guard.Stop();
#endif
        modelnet::GuardTable table;modelnet::GuardPermit permit;
        Check(!table.Prepare("observe","fp",1,std::numeric_limits<int64_t>::max(),permit,error) && error=="BTX035_CLOCK","overflow clock rejected before signed addition");
        Check(table.Prepare("observe","fp",1,1000,permit,error),"valid test table permit");
        Check(!table.Execute(permit.secret,999,reply,error) && error=="BTX035_CLOCK","clock rollback fails closed");
        Check(table.Paused(),"clock rollback pauses issuance");
        modelnet::GuardTable bounded;
        for(size_t i=0;i<modelnet::GuardTable::kMaxPermits;++i) {
            if(!bounded.Prepare("observe","bounded",1,1000,permit,error))throw std::runtime_error("native bounded table fill");
        }
        Check(!bounded.Prepare("observe","bounded",1,1000,permit,error) && error=="BTX035_LIMIT","permit table cannot exceed its resource bound");
        Check(bounded.Prepare("observe","bounded",1,1000+modelnet::GuardTable::kPermitTtlMs+1,permit,error),"expired permits are reclaimed before admitting a new token");
        std::cout<<"{\"guard_process_checks_passed\":"<<checks<<",\"physical_execution_claimed\":false}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
