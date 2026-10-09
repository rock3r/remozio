/* Disposable unprivileged experiment. Never embed or install this fixture. */
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t continued=0;
static void note(int number){(void)number;continued=1;}
int main(void){sigset_t blocked,original;sigemptyset(&blocked);sigaddset(&blocked,SIGCONT);if(sigprocmask(SIG_BLOCK,&blocked,&original))return 95;signal(SIGCONT,note);if(write(1,"READY\n",6)!=6)return 60;while(!continued)sigsuspend(&original);if(write(1,"RESUMED\n",8)!=8)return 61;return 7;}
