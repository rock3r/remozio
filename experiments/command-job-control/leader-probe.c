/* Disposable unprivileged experiment. Never embed or install this fixture. */
#include "RemozioCommandProcess.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
static int stopped(pid_t pid,int *number){siginfo_t info={0};if(waitid(P_PID,(id_t)pid,&info,WSTOPPED|WNOHANG|WNOWAIT))return -1;if(info.si_pid==pid&&info.si_code==CLD_STOPPED){*number=info.si_status;return 1;}return 0;}
int main(int argc,char **argv){
    if(argc!=3)return 40;
    FILE *file=fopen(argv[2],"rb");if(!file)return 41;unsigned char frame[4096];size_t count=fread(frame,1,sizeof frame,file);fclose(file);
    remozio_command_pty_t *pty=NULL;remozio_command_process_t *process=NULL;int directory=-1,slave=-1,result=1;
    if(remozio_command_pty_create(NULL,NULL,&pty)||remozio_command_pty_borrow_slave(pty,&slave))goto cleanup;
    struct termios raw;if(tcgetattr(slave,&raw))goto cleanup;cfmakeraw(&raw);if(tcsetattr(slave,TCSANOW,&raw))goto cleanup;
    directory=open("/tmp",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(directory<0)goto cleanup;
    if(remozio_command_process_spawn(argv[1],frame,count,slave,slave,slave,directory,&process))goto cleanup;
    remozio_command_pty_seal_slave(pty);remozio_command_process_observation_t observation={0};
    for(int i=0;i<5000&&!observation.prepared;i++){if(remozio_command_process_poll(process,&observation))goto cleanup;usleep(1000);}
    if(!observation.prepared||remozio_command_process_release(process))goto cleanup;
    char output[1024]={0};size_t used=0;bool eof=false;
    for(int i=0;i<5000&&used<6;i++){size_t got=0;if(remozio_command_process_poll(process,&observation)||remozio_command_pty_read(pty,output+used,sizeof output-used,&got,&eof))goto cleanup;used+=got;usleep(1000);}
    if(used!=6||memcmp(output,"READY\n",6)||!observation.exec_observed)goto cleanup;
    if(remozio_command_pty_signal(pty,SIGTSTP))goto cleanup;
    int tstp_stop=0,number=0;
    for(int i=0;i<100;i++){int found=stopped(observation.pid,&number);if(found<0)goto cleanup;if(found){tstp_stop=number==SIGTSTP;break;}if(remozio_command_process_poll(process,&observation))goto cleanup;usleep(1000);}
    if(remozio_command_pty_signal(pty,SIGSTOP))goto cleanup;
    int hard_stop=0;
    for(int i=0;i<1000;i++){int found=stopped(observation.pid,&number);if(found<0)goto cleanup;if(found){hard_stop=number==SIGSTOP;break;}usleep(1000);}
    if(!hard_stop||remozio_command_process_poll(process,&observation)||observation.reaped||observation.ownership_lost)goto cleanup;
    int poll_keeps_owned=observation.exec_observed&&!observation.reaped;
    if(remozio_command_pty_signal(pty,SIGCONT))goto cleanup;
    for(int i=0;i<5000&&!observation.reaped;i++){size_t got=0;if(remozio_command_process_poll(process,&observation)||remozio_command_pty_read(pty,output+used,sizeof output-used,&got,&eof))goto cleanup;used+=got;usleep(1000);}
    for(int i=0;i<100&&!eof;i++){size_t got=0;if(remozio_command_pty_read(pty,output+used,sizeof output-used,&got,&eof))goto cleanup;used+=got;usleep(1000);}
    int exit7=observation.reaped&&observation.exec_observed&&!observation.ownership_lost&&WIFEXITED(observation.wait_status)&&WEXITSTATUS(observation.wait_status)==7;
    int exact=used==14&&!memcmp(output,"READY\nRESUMED\n",14);
    printf("{\"foregroundSIGTSTPStoppedLeader\":%s,\"foregroundSIGSTOPStoppedLeader\":%s,\"nativePollRetainedOwnedStoppedChild\":%s,\"foregroundContinueProducedActualExit7\":%s,\"exactOutput\":%s}\n",tstp_stop?"true":"false",hard_stop?"true":"false",poll_keeps_owned?"true":"false",exit7?"true":"false",exact?"true":"false");
    result=!(hard_stop&&poll_keeps_owned&&exit7&&exact);
cleanup:
    if(process){remozio_command_process_cancel(process);for(int i=0;i<5000&&remozio_command_process_dispose(process);i++){remozio_command_process_observation_t o;remozio_command_process_poll(process,&o);usleep(1000);}}
    if(pty)remozio_command_pty_close(pty);if(directory>=0)close(directory);return result;
}
