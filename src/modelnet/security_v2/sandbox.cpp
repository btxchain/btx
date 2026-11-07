// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <modelnet/security_v2/sandbox.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <thread>
#if defined(__linux__)
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <elf.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#endif
namespace modelnet::security {
    std::string StaticSandboxDigest() {
        return DomainHash("BTX/SandboxProfile/v1","linux-static-fd-v1:sealed-static-elf:stdin-only:bounded-stdout:no-open:no-socket:no-clone:no-reexec:rlimits:pdeathsig:release-fence");
    }
#if defined(__linux__)
    namespace {
        class FD {
            public:int n {
                -1
            };
            FD()=default;
            explicit FD(int fd):n(fd) {
            }
            ~FD() {
                if(n>=0)close(n);
            }
            FD(const FD&)=delete;
            void reset(int fd=-1) {
                if(n>=0)close(n);
                n=fd;
            }
        };
        bool StaticElf(std::string_view data) {
            if(data.size()<sizeof(Elf64_Ehdr))return false;
            Elf64_Ehdr h {
            };
            std::memcpy(&h,data.data(),sizeof(h));
            if(std::memcmp(h.e_ident,ELFMAG,SELFMAG)!=0||h.e_ident[EI_CLASS]!=ELFCLASS64||h.e_ident[EI_DATA]!=ELFDATA2LSB||(h.e_type!=ET_EXEC&&h.e_type!=ET_DYN)||h.e_phnum==0||h.e_phnum>256||h.e_phentsize!=sizeof(Elf64_Phdr))return false;
#if defined(__x86_64__)
            if(h.e_machine!=EM_X86_64)return false;
#elif defined(__aarch64__)
            if(h.e_machine!=EM_AARCH64)return false;
#else
            return false;
#endif
            if(h.e_phoff>data.size()||static_cast<uint64_t>(h.e_phnum)*sizeof(Elf64_Phdr)>data.size()-h.e_phoff)return false;
            for(size_t i=0; i<h.e_phnum; ++i) {
                Elf64_Phdr p {
                };
                std::memcpy(&p,data.data()+h.e_phoff+i*sizeof(p),sizeof(p));
                if(p.p_type==PT_INTERP||p.p_type==PT_DYNAMIC)return false;
            }
            return true;
        }
        std::vector<sock_filter> Filter() {
            std::vector<sock_filter> f;
            auto stmt=[&](uint16_t code,uint32_t k) {
                f.push_back(BPF_STMT(code,k));
            };
            auto jump=[&](uint16_t code,uint32_t k,uint8_t yes,uint8_t no) {
                f.push_back(BPF_JUMP(code,k,yes,no));
            };
            stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,arch));
#if defined(__x86_64__)
            jump(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0);
#elif defined(__aarch64__)
            jump(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0);
#else
#error unsupported Linux seccomp architecture
#endif
            stmt(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
            stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr));
            // The initial exec is allowed only through fd 3, which is CLOEXEC. No fd
            // creation/duplication syscall is permitted after exec, so 3 cannot return.
            jump(BPF_JMP|BPF_JEQ|BPF_K,SYS_execveat,0,4);
            stmt(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args[0]));
            jump(BPF_JMP|BPF_JEQ|BPF_K,3,0,1);
            stmt(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
            stmt(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM);
            const int allowed[]= {
                SYS_read,SYS_write,SYS_readv,SYS_writev,SYS_close,SYS_fstat,SYS_lseek,
                SYS_mmap,SYS_mprotect,SYS_munmap,SYS_brk,SYS_madvise,SYS_mremap,
                SYS_rt_sigaction,SYS_rt_sigprocmask,SYS_rt_sigreturn,SYS_sigaltstack,
                SYS_exit,SYS_exit_group,SYS_futex,SYS_set_tid_address,SYS_set_robust_list,
                SYS_clock_gettime,SYS_clock_nanosleep,SYS_nanosleep,SYS_gettimeofday,
                SYS_getpid,SYS_getppid,SYS_gettid,SYS_getuid,SYS_geteuid,SYS_getgid,SYS_getegid,
                SYS_sched_yield,SYS_getrusage,SYS_uname,SYS_getrandom,
#ifdef SYS_arch_prctl
                SYS_arch_prctl,
#endif
#ifdef SYS_rseq
                SYS_rseq,
#endif
#ifdef SYS_getrlimit
                SYS_getrlimit,
#endif
#ifdef SYS_restart_syscall
                SYS_restart_syscall,
#endif
            };
            for(int nr:allowed) {
                jump(BPF_JMP|BPF_JEQ|BPF_K,nr,0,1);
                stmt(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
            }
            stmt(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM);
            return f;
        }
        bool Limit(int which,rlim_t value) {
            rlimit r {
                value,value
            };
            return setrlimit(which,&r)==0;
        }
        void Nonblock(int fd) {
            int flags=fcntl(fd,F_GETFL,0);
            Require(flags>=0&&fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0,"SEC_PIPE");
        }
    }
#endif
    SandboxResult RunStaticWorker(const fs::path& executable,const std::string& digest,std::string_view input,
    const SandboxLimits& lim,const std::function<bool()>& authorized) {
        SandboxResult out;
        out.profile="linux-static-fd-v1";
        out.executable_digest=digest;
        Require(IsHash(digest)&&input.size()<=16*1024*1024,"SEC_WORKER_INPUT");
        Require(lim.memory_bytes>=16*1024*1024&&lim.memory_bytes<=64ull*1024*1024*1024&&lim.wall_ms>0&&lim.wall_ms<=600000&&lim.cpu_ms>0&&lim.cpu_ms<=lim.wall_ms&&lim.output_bytes>0&&lim.output_bytes<=16*1024*1024,
        "SEC_WORKER_LIMITS");
#if !defined(__linux__)
        (void)executable;
        (void)authorized;
        out.error="SEC_STATIC_FD_PLATFORM_UNAVAILABLE";
        return out;
#else
        const auto bytes=ReadFile(executable,128*1024*1024);
        Require(Hash(bytes)==digest,"SEC_EXECUTABLE_DIGEST");
        Require(StaticElf(bytes),"SEC_STATIC_ELF_REQUIRED");
        FD sealed(static_cast<int>(syscall(SYS_memfd_create,"btx-verified-executable",MFD_ALLOW_SEALING|MFD_CLOEXEC)));
        if(sealed.n<0) {
            out.error="SEC_MEMFD_UNAVAILABLE";
            return out;
        }
        size_t written=0;
        while(written<bytes.size()) {
            ssize_t n=write(sealed.n,bytes.data()+written,bytes.size()-written);
            if(n<0&&errno==EINTR)continue;
            Require(n>0,"SEC_EXECUTABLE_STAGE");
            written+=n;
        }
        Require(fchmod(sealed.n,0500)==0&&fcntl(sealed.n,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)==0,
        "SEC_EXECUTABLE_SEAL");
        auto filter=Filter();
        sock_fprog program {
            static_cast<unsigned short>(filter.size()),filter.data()
        };
        int in[2],outs[2],status[2];
        Require(pipe2(in,O_CLOEXEC)==0,"SEC_PIPE");
        FD readin(in[0]),writein(in[1]);
        Require(pipe2(outs,O_CLOEXEC)==0,"SEC_PIPE");
        FD readout(outs[0]),writeout(outs[1]);
        Require(pipe2(status,O_CLOEXEC)==0,"SEC_PIPE");
        FD readstatus(status[0]),writestatus(status[1]);
        FD nullfd(open("/dev/null",O_WRONLY|O_CLOEXEC));
        Require(nullfd.n>=0,"SEC_NULL");
        // Move source descriptors away from 0..4 so dup2 does not clobber a source.
        FD exec_src(fcntl(sealed.n,F_DUPFD_CLOEXEC,10)),in_src(fcntl(readin.n,F_DUPFD_CLOEXEC,10)),out_src(fcntl(writeout.n,
        F_DUPFD_CLOEXEC,10)),err_src(fcntl(nullfd.n,F_DUPFD_CLOEXEC,10)),status_src(fcntl(writestatus.n,F_DUPFD_CLOEXEC,
        10));
        Require(exec_src.n>=0&&in_src.n>=0&&out_src.n>=0&&err_src.n>=0&&status_src.n>=0,"SEC_DUP");
        char name[]="btx-verified-worker";
        char* argv[] {
            name,nullptr
        };
        char locale[]="LANG=C";
        char* env[] {
            locale,nullptr
        };
        const pid_t parent=getpid();
        const auto started=std::chrono::steady_clock::now();
        Require(authorized(),"SEC_REVOKED_BEFORE_EXEC");
        pid_t pid=fork();
        Require(pid>=0,"SEC_FORK");
        if(pid==0) {
            // No C++ allocation, destructors or locks after fork in a threaded guard.
            if(dup2(in_src.n,0)<0||dup2(out_src.n,1)<0||dup2(err_src.n,2)<0||dup3(exec_src.n,3,O_CLOEXEC)<0||dup3(status_src.n,
            4,O_CLOEXEC)<0)_exit(125);
            auto fail=[]() {
                const unsigned char e=1;
                // A dropped failure byte looks like a successful CLOEXEC exec.
                for(;;) {
                    const ssize_t n=write(4,&e,1);
                    if(n==1||(n<0&&errno!=EINTR))break;
                }
                _exit(125);
            };
            if(setpgid(0,0)!=0||prctl(PR_SET_PDEATHSIG,SIGKILL)!=0||getppid()!=parent||prctl(PR_SET_NO_NEW_PRIVS,
            1,0,0,0)!=0)fail();
            if(!Limit(RLIMIT_AS,lim.memory_bytes)||!Limit(RLIMIT_CPU,(lim.cpu_ms+999)/1000)||!Limit(RLIMIT_CORE,
            0)||!Limit(RLIMIT_FSIZE,0)||!Limit(RLIMIT_NOFILE,5)||!Limit(RLIMIT_NPROC,1))fail();
#ifdef SYS_close_range
            if(syscall(SYS_close_range,5U,~0U,0)!=0)for(int fd=5; fd<65536; ++fd)close(fd);
#else
            for(int fd=5; fd<65536; ++fd)close(fd);
#endif
            if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)!=0)fail();
            syscall(SYS_execveat,3,"",argv,env,AT_EMPTY_PATH);
            fail();
        }
        setpgid(pid,pid);
        readin.reset();
        writeout.reset();
        writestatus.reset();
        exec_src.reset();
        in_src.reset();
        out_src.reset();
        err_src.reset();
        status_src.reset();
        Nonblock(writein.n);
        Nonblock(readout.n);
        Nonblock(readstatus.n);
        size_t sent=0;
        bool finished=false,stdout_eof=false,exec_closed=false,setup_failed=false;
        int child_status=0;
        // SIGPIPE is blocked only on this thread; no process-global disposition.
        sigset_t block,previous,prior_pending;
        sigpending(&prior_pending);
        const bool prior_sigpipe=sigismember(&prior_pending,SIGPIPE)==1;
        sigemptyset(&block);
        sigaddset(&block,SIGPIPE);
        pthread_sigmask(SIG_BLOCK,&block,&previous);
        try {
            while(!finished||!stdout_eof) {
                const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
                if(!finished&&(static_cast<uint64_t>(elapsed)>=lim.wall_ms||!authorized())) {
                    out.timed_out=static_cast<uint64_t>(elapsed)>=lim.wall_ms;
                    out.cancelled=!out.timed_out;
                    kill(-pid,SIGKILL);
                    kill(pid,SIGKILL);
                }
                pollfd fds[3] {
                    {
                        readout.n,POLLIN,0
                    }, {
                        writein.n,static_cast<short>(writein.n>=0?POLLOUT:0),0
                    }, {
                        readstatus.n,POLLIN,0
                    }
                };
                poll(fds,3,10);
                if(writein.n>=0) {
                    if(sent==input.size())writein.reset();
                    else if(fds[1].revents&(POLLOUT|POLLERR|POLLHUP)) {
                        ssize_t n=write(writein.n,input.data()+sent,std::min<size_t>(8192,input.size()-sent));
                        if(n>0)sent+=n;
                        else if(n<0&&errno!=EAGAIN&&errno!=EINTR)writein.reset();
                    }
                }
                std::array<char,8192> buffer {
                };
                while(!stdout_eof) {
                    ssize_t n=read(readout.n,buffer.data(),buffer.size());
                    if(n>0) {
                        if(out.output.size()+static_cast<size_t>(n)>lim.output_bytes) {
                            out.error="SEC_OUTPUT_LIMIT";
                            kill(-pid,SIGKILL);
                            kill(pid,SIGKILL);
                            stdout_eof=true;
                            break;
                        }
                        out.output.append(buffer.data(),n);
                    }
                    else if(n==0) {
                        stdout_eof=true;
                        break;
                    }
                    else if(errno==EINTR)continue;
                    else break;
                }
                if(!exec_closed) {
                    unsigned char b=0;
                    ssize_t n=read(readstatus.n,&b,1);
                    if(n>0)setup_failed=true;
                    else if(n==0)exec_closed=true;
                }
                if(!finished) {
                    pid_t r=waitpid(pid,&child_status,WNOHANG);
                    if(r==pid)finished=true;
                    else if(r<0&&errno!=EINTR)throw Error("SEC_WAIT");
                }
                if(finished&&stdout_eof)break;
            }
        }
        catch(...) {
            kill(-pid,SIGKILL);
            kill(pid,SIGKILL);
            while(waitpid(pid,&child_status,0)<0&&errno==EINTR) {
            }
            sigset_t pending;
            sigpending(&pending);
            if(!prior_sigpipe&&sigismember(&pending,SIGPIPE)) {
                int sig=0;
                sigwait(&block,&sig);
            }
            pthread_sigmask(SIG_SETMASK,&previous,nullptr);
            throw;
        }
        sigset_t pending;
        sigpending(&pending);
        if(!prior_sigpipe&&sigismember(&pending,SIGPIPE)) {
            int sig=0;
            sigwait(&block,&sig);
        }
        pthread_sigmask(SIG_SETMASK,&previous,nullptr);
        out.elapsed_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
        out.dispatched=exec_closed&&!setup_failed;
        out.enforced=out.dispatched;
        out.exit_code=WIFEXITED(child_status)?WEXITSTATUS(child_status):WIFSIGNALED(child_status)?128+WTERMSIG(child_status):-1;
        if(setup_failed)out.error="SEC_SANDBOX_SETUP_UNAVAILABLE";
        else if(out.cancelled)out.error="SEC_REVOKED_DURING_EXEC";
        else if(out.timed_out)out.error="SEC_TIMEOUT";
        else if(out.exit_code!=0&&out.error.empty())out.error="SEC_WORKER_EXIT";
        if(!authorized()) {
            out.cancelled=true;
            out.error="SEC_RELEASE_REVOKED";
            out.output.clear();
        }
        if(!out.error.empty())out.output.clear();
        return out;
#endif
    }
}
// namespace modelnet::security
