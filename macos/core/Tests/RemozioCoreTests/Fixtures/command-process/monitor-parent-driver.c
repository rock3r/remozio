/* Disposable unprivileged parent candidate validation. Never installs a service. */
#include "RemozioCommandMonitor.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static uint64_t milliseconds(void) { struct timespec time; clock_gettime(CLOCK_MONOTONIC,&time); return (uint64_t)time.tv_sec*1000+(uint64_t)time.tv_nsec/1000000; }
static int await_state(remozio_command_monitor_t *monitor, remozio_command_monitor_observation_t *state, unsigned phase) {
    uint64_t deadline=milliseconds()+8000;
    do {
        int error=remozio_command_monitor_poll(monitor,state);
        if ((phase==0&&state->prepared)||(phase==1&&state->status.latest.tag==REMOZIO_MONITOR_JOB_STATE&&(state->status.latest.flags&REMOZIO_MONITOR_STOPPED))||(phase==2&&state->monitor_reaped&&state->status_closed)) return 0;
        if(error) return error;
        usleep(1000);
    } while(milliseconds()<deadline);
    return ETIMEDOUT;
}
int main(int argc,char **argv) {
    if(argc!=5)return 1;
    bool late=!strcmp(argv[4],"late_observation");
    bool exec_failure=!strcmp(argv[4],"exec_failure");
    bool terminal=strstr(argv[4],"pty_")==argv[4];
    bool cancel=!strcmp(argv[4],"cancel")||!strcmp(argv[4],"pty_cancel"),stop=!strcmp(argv[4],"stop_resume")||!strcmp(argv[4],"pty_stop_resume"),immediate=!strcmp(argv[4],"immediate_cancel");
    FILE *file=fopen(argv[3],"rb");if(!file)return 2;
    unsigned char frame[8192];size_t count=fread(frame,1,sizeof(frame),file);fclose(file);
    int input[2],output[2],error_pipe[2];if(pipe(input)||pipe(output)||pipe(error_pipe))return 3;
    write(input[1],"unread",6);close(input[1]);int flags=fcntl(input[0],F_GETFL),directory=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    remozio_command_pty_t *pty=NULL;int slave=-1;
    remozio_command_monitor_t *monitor=NULL;remozio_command_monitor_observation_t state={0};int failure=0;
    if(!strcmp(argv[4],"preflight")){
        struct sigaction old,ignored={0};if(sigaction(SIGCHLD,NULL,&old)){failure=20;goto cleanup;}
        ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);
        if(sigaction(SIGCHLD,&ignored,NULL)){failure=20;goto cleanup;}
        int result=remozio_command_monitor_spawn(argv[1],argv[2],frame,count,input[0],output[1],error_pipe[1],directory,&monitor);
        (void)sigaction(SIGCHLD,&old,NULL);
        if(result!=EINVAL||monitor){failure=21;goto cleanup;}
        ignored.sa_handler=SIG_DFL;ignored.sa_flags=SA_NOCLDWAIT;
        if(sigaction(SIGCHLD,&ignored,NULL)){failure=20;goto cleanup;}
        result=remozio_command_monitor_spawn(argv[1],argv[2],frame,count,input[0],output[1],error_pipe[1],directory,&monitor);
        (void)sigaction(SIGCHLD,&old,NULL);
        if(result!=EINVAL||monitor){failure=22;goto cleanup;}
        if(remozio_command_monitor_spawn("/nonexistent/remozio-monitor",argv[2],frame,count,input[0],output[1],error_pipe[1],directory,&monitor)!=ENOENT||monitor){failure=23;goto cleanup;}
        if(remozio_command_monitor_spawn(argv[1],argv[2],frame,count,input[0],input[0],error_pipe[1],directory,&monitor)!=EINVAL||monitor){failure=24;goto cleanup;}
        int available=0;if(ioctl(input[0],FIONREAD,&available)||available!=6||fcntl(input[0],F_GETFL)!=flags){failure=25;goto cleanup;}
        goto cleanup;
    }
    if(terminal){if(remozio_command_pty_create(NULL,NULL,&pty)||remozio_command_pty_borrow_slave(pty,&slave)){failure=19;goto cleanup;}struct termios attributes;if(tcgetattr(slave,&attributes)){failure=19;goto cleanup;}cfmakeraw(&attributes);if(tcsetattr(slave,TCSANOW,&attributes)){failure=19;goto cleanup;}}
    if(remozio_command_monitor_spawn(argv[1],argv[2],frame,count,terminal?slave:input[0],terminal?slave:output[1],terminal?slave:error_pipe[1],directory,&monitor)||!monitor){failure=4;goto cleanup;}
    if(pty)remozio_command_pty_seal_slave(pty);
    close(output[1]);output[1]=-1;close(error_pipe[1]);error_pipe[1]=-1;
    if(immediate){if(remozio_command_monitor_cancel(monitor)){failure=5;goto cleanup;}}
    else {
        if(await_state(monitor,&state,0)||!state.target_kernel_registered||state.target_exec_observed||state.release_attempted){failure=6;goto cleanup;}
        int available=0;if(ioctl(input[0],FIONREAD,&available)||available!=6||fcntl(input[0],F_GETFL)!=flags){failure=7;goto cleanup;}
        if(remozio_command_monitor_dispose(monitor)!=EBUSY||remozio_command_monitor_signal(monitor,SIGCONT)!=EAGAIN){failure=8;goto cleanup;}
        if(cancel){if(remozio_command_monitor_cancel(monitor)){failure=9;goto cleanup;}}
        else {
            if(remozio_command_monitor_release(monitor)||remozio_command_monitor_release(monitor)!=EALREADY){failure=10;goto cleanup;}
            if(stop){if(await_state(monitor,&state,1)||!state.target_exec_observed||remozio_command_monitor_signal(monitor,SIGCONT)){failure=11;goto cleanup;}}
            if(late){uint64_t deadline=milliseconds()+8000;
                while((!state.status.failed||!state.target_exec_observed)&&milliseconds()<deadline){if(remozio_command_monitor_poll(monitor,&state)){failure=26;goto cleanup;}usleep(1000);}
                if(!state.status.failed||!state.target_exec_observed||state.monitor_reaped||state.target_exit_observed||remozio_command_monitor_signal(monitor,SIGTERM)){failure=27;goto cleanup;}
            }
        }
    }
    if(await_state(monitor,&state,2)){failure=12;goto cleanup;}
    if(state.target_exec_observed!=(bool)(!cancel&&!immediate&&!exec_failure)||(!immediate&&(!state.status.reaped||!state.target_exit_observed))||state.monitor_ownership_lost){failure=13;goto cleanup;}
    if(!cancel&&!immediate){
        if(state.status.failed!=(exec_failure||late)||state.status.latest.detail!=(uint32_t)(late?SIGTERM:(exec_failure?70:7)<<8)||state.monitor_wait_status!=((exec_failure||late)?70<<8:0)||!state.status.target_release_attempted||(exec_failure&&state.status.failure_error!=ENOENT)||(late&&state.status.failure_error!=EPROTO)){failure=14;goto cleanup;}
        if(!stop&&!terminal&&!exec_failure&&!late){char out[64],err[16];if(read(output[0],out,sizeof(out))!=10||memcmp(out,"OUT:unread",10)||read(error_pipe[0],err,sizeof(err))!=3||memcmp(err,"ERR",3)){failure=15;goto cleanup;}}
    }else if(!immediate){int actual=(int)state.status.latest.detail;if(state.release_attempted||state.status.target_release_attempted||(!WIFSIGNALED(actual)&&!(WIFEXITED(actual)&&WEXITSTATUS(actual)==70))){failure=16;goto cleanup;}}
    if(remozio_command_monitor_signal(monitor,SIGTERM)!=ESRCH){failure=17;goto cleanup;}
cleanup:
    if(monitor){
        (void)remozio_command_monitor_cancel(monitor);uint64_t deadline=milliseconds()+10000;
        while(!state.monitor_reaped&&!state.monitor_ownership_lost&&milliseconds()<deadline){(void)remozio_command_monitor_poll(monitor,&state);usleep(1000);}
        if(remozio_command_monitor_dispose(monitor))failure=18;
    }
    remozio_command_pty_close(pty);
    close(input[0]);close(output[0]);close(error_pipe[0]);if(output[1]>=0)close(output[1]);if(error_pipe[1]>=0)close(error_pipe[1]);if(directory>=0)close(directory);
    printf("{\"case\":\"%s\",\"failure\":%d,\"independentExec\":%s,\"independentExit\":%s,\"monitorActuallyReaped\":%s,\"targetReapedReport\":%s}\n",argv[4],failure,state.target_exec_observed?"true":"false",state.target_exit_observed?"true":"false",state.monitor_reaped?"true":"false",state.status.reaped?"true":"false");
    return failure?1:0;
}
