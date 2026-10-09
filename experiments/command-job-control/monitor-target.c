/* Disposable unprivileged experiment. Never embed or install this fixture. */
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t resumed;
static void continued(int number){(void)number;resumed=1;}
int main(void){
 for(int fd=3;fd<256;fd++)if(fcntl(fd,F_GETFD)>=0)return 91;
 if(getsid(0)==getpid()||tcgetpgrp(0)!=getpgrp()||getpgrp()!=getpid())return 92;
 sigset_t blocked,original;sigemptyset(&blocked);sigaddset(&blocked,SIGCONT);if(sigprocmask(SIG_BLOCK,&blocked,&original))return 95;
 struct sigaction action={0};action.sa_handler=continued;sigemptyset(&action.sa_mask);sigaction(SIGCONT,&action,0);
 if(write(1,"READY\n",6)!=6)return 93;
 while(!resumed)sigsuspend(&original);if(write(1,"RESUMED\n",8)!=8)return 94;return 7;
}
