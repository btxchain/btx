/* Defensive fixture: no real credentials or external destination are used. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    char input[256]={0}; ssize_t n=read(0,input,sizeof(input)-1); if(n<0)return 20;
    if(strstr(input,"sleep")){sleep(20);return 21;}
    if(strstr(input,"flood")){for(int i=0;i<100000;++i)puts("untrusted-output");return 0;}
    errno=0;int fd=open("/etc/passwd",O_RDONLY);int file_denied=fd<0&&errno==EPERM;if(fd>=0)close(fd);
    errno=0;int sock=socket(AF_INET,SOCK_STREAM,0);int net_denied=sock<0&&errno==EPERM;if(sock>=0)close(sock);
    errno=0;pid_t child=fork();int fork_denied=child<0&&errno==EPERM;if(child==0)_exit(22);
    if(!file_denied||!net_denied||!fork_denied||getenv("BTX_SECRET_SENTINEL")!=NULL)return 23;
    puts("{\"filesystem_denied\":true,\"network_denied\":true,\"fork_denied\":true,\"environment_clean\":true}");
    return 0;
}
