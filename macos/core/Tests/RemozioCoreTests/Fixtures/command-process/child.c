/* Unprivileged synthetic launcher and program. This fixture is never embedded or installed. */
#include "RemozioCommandChild.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
static uint32_t word(const unsigned char *b) { return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3]; }
static int exact(int fd, void *value, size_t count) {
    size_t used=0;
    while(used<count) {
        ssize_t n=read(fd,(char *)value+used,count-used);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return 1;
        used+=(size_t)n;
    }
    return 0;
}
int main(int argc, char **argv) {
    if(argc==2 && !strcmp(argv[1],"--execute")) {
        if(strstr(argv[0],"stalled-child")) {for(;;)pause();}
        unsigned char header[40]={0};
        if(exact(3,header,40))return 70;
        size_t count=40+word(header+4);
        if(count>REMOZIO_CHILD_MAX_BYTES)return 70;
        unsigned char *bytes=malloc(count);if(!bytes)return 70;
        memcpy(bytes,header,40);if(exact(3,bytes+40,count-40))return 70;
        unsigned char extra=0;if(read(3,&extra,1)!=0)return 70;close(3);
        remozio_child_spec_t spec={0};if(remozio_child_spec_decode(bytes,count,&spec))return 70;free(bytes);
        if(fchdir(4))return 70;close(4);
        if(spec.io_mode==1 && (getsid(0)!=getpid() || ioctl(0,TIOCSCTTY,0)))return 70;
        if(fcntl(5,F_SETFD,FD_CLOEXEC))return 70;
        unsigned char ready[12]={0x52,0x4d,0x52,0x31,0,0,0,1,0,0,0,0};
        if(strstr(argv[0],"malformed-child")) {ready[0]=0;write(5,ready,12);return 70;}
        if(strstr(argv[0],"truncated-child")) {write(5,ready,7);return 70;}
        if(strstr(argv[0],"closed-release-child"))close(6);
        if(write(5,ready,12)!=12)return 70;
        if(strstr(argv[0],"closed-release-child")) {for(;;)pause();}
        unsigned char release=0;if(exact(6,&release,1)||release!=1)return 70;close(6);
        if(strstr(argv[0],"late-fault-child")) {unsigned char extra=1;write(5,&extra,1);}
        execve(spec.executable,spec.arguments,spec.environment);
        return 70;
    }
    if(argc!=4 || (unsigned char)argv[0][0]!=0xff || argv[0][1] || argv[1][0] ||
        (unsigned char)argv[2][0]!=0xfe || argv[2][1])return 91;
    char *raw=getenv("RAW"), *empty=getenv("EMPTY");
    if(!raw || (unsigned char)raw[0]!=0xfd || raw[1] || !empty || *empty || getenv("PATH"))return 92;
    for(int fd=3;fd<256;fd++)if(fcntl(fd,F_GETFD)>=0)return 93;
    if(getpgrp()!=getpid())return 94;
    if(!strcmp(argv[3],"pty")) {if(!isatty(0)||getsid(0)!=getpid()||tcgetpgrp(0)!=getpgrp())return 99;return write(1,"PTY",3)==3?7:98;}
    if(!strcmp(argv[3],"pty-bulk") || !strcmp(argv[3],"pty-infinite")) {
        if(!isatty(0)||getsid(0)!=getpid()||tcgetpgrp(0)!=getpgrp())return 99;
        size_t offset=0;unsigned char block[4096];
        do {
            for(size_t i=0;i<sizeof(block);i++)block[i]=(unsigned char)((offset+i)%251);
            size_t used=0;
            while(used<sizeof(block)) {
                ssize_t n=write(1,block+used,sizeof(block)-used);
                if(n<0&&errno==EINTR)continue;
                if(n<=0)return 98;
                used+=(size_t)n;
            }
            offset+=sizeof(block);
        } while(!strcmp(argv[3],"pty-infinite")||offset<1048576);
        return 7;
    }
    if(!strcmp(argv[3],"signal")) {raise(SIGTERM);return 95;}
    if(!strcmp(argv[3],"short-wait")) {usleep(300000);return 0;}
    if(!strcmp(argv[3],"wait")) {for(;;)pause();}
    if(!strcmp(argv[3],"sigwait")) {
        sigset_t signals;sigemptyset(&signals);sigaddset(&signals,SIGCONT);
        if(sigprocmask(SIG_BLOCK,&signals,NULL)||write(1,"WAIT\n",5)!=5)return 101;
        for(;;){int number=0;if(sigwait(&signals,&number)||number!=SIGCONT)return 102;}
    }
    struct stat held,named;if(stat(".",&held)||stat(getenv("CWD"),&named)||held.st_ino!=named.st_ino||held.st_dev!=named.st_dev)return 96;
    char input[64]={0};ssize_t n=read(0,input,sizeof(input));if(n<0)return 97;
    if(write(1,"OUT:",4)!=4 || write(1,input,(size_t)n)!=n || write(2,"ERR",3)!=3)return 98;
    return 7;
}
