/* Disposable unprivileged parent candidate validation. Never installs a service. */
#include "RemozioCommandMonitor.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
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
static int await_waiting_target(remozio_command_pty_t *pty,int output) {
    unsigned char bytes[5];size_t received=0;uint64_t deadline=milliseconds()+5000;
    if(!pty){int flags=fcntl(output,F_GETFL);if(flags<0||fcntl(output,F_SETFL,flags|O_NONBLOCK))return errno;}
    do{
        if(pty){size_t count=0;bool eof=false;int error=remozio_command_pty_read(pty,bytes+received,sizeof(bytes)-received,&count,&eof);if(error)return error;if(eof)return EPIPE;received+=count;}
        else{ssize_t count=read(output,bytes+received,sizeof(bytes)-received);if(count>0)received+=(size_t)count;else if(!count)return EPIPE;else if(errno!=EINTR&&errno!=EAGAIN)return errno;}
        if(received==sizeof(bytes))return memcmp(bytes,"WAIT\n",sizeof(bytes))?EPROTO:0;
        usleep(1000);
    }while(milliseconds()<deadline);
    return ETIMEDOUT;
}
int main(int argc,char **argv) {
    if(argc!=5)return 1;
    bool current=strstr(argv[4],"current_job")!=NULL;
    bool current_checked=false, queued_checked=false, monitor_paused=false;
    bool queued=strstr(argv[4],"queued_current_job")!=NULL;
    bool late=!strcmp(argv[4],"late_observation");
    bool exec_failure=!strcmp(argv[4],"exec_failure");
    bool terminal=strstr(argv[4],"pty_")==argv[4];
    bool cancel=!strcmp(argv[4],"cancel")||!strcmp(argv[4],"pty_cancel"),stop=!strcmp(argv[4],"stop_resume")||!strcmp(argv[4],"pty_stop_resume"),immediate=!strcmp(argv[4],"immediate_cancel");
    FILE *file=fopen(argv[3],"rb");if(!file)return 2;
    unsigned char frame[8192];size_t count=fread(frame,1,sizeof(frame),file);fclose(file);
    int input[2],output[2],error_pipe[2];if(pipe(input)||pipe(output)||pipe(error_pipe))return 3;
    write(input[1],"unread",6);close(input[1]);int flags=fcntl(input[0],F_GETFL),directory=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    remozio_command_pty_t *pty=NULL;int slave=-1;
    remozio_command_monitor_t *monitor=NULL;remozio_command_monitor_observation_t state={0};remozio_command_current_job_t job={0};int failure=0;
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
        if(current && (remozio_command_monitor_current_job(monitor,&job)||job.known)){failure=30;goto cleanup;}
        int available=0;if(ioctl(input[0],FIONREAD,&available)||available!=6||fcntl(input[0],F_GETFL)!=flags){failure=7;goto cleanup;}
        if(remozio_command_monitor_dispose(monitor)!=EBUSY||remozio_command_monitor_signal(monitor,SIGCONT)!=EAGAIN){failure=8;goto cleanup;}
        if(cancel){if(remozio_command_monitor_cancel(monitor)){failure=9;goto cleanup;}}
        else {
            if(remozio_command_monitor_release(monitor)||remozio_command_monitor_release(monitor)!=EALREADY){failure=10;goto cleanup;}
            if(current){
                if(await_waiting_target(pty,output[0])){failure=39;goto cleanup;}
                uint64_t deadline=milliseconds()+5000;
                while(!state.target_exec_observed && milliseconds()<deadline){if(remozio_command_monitor_poll(monitor,&state)){failure=31;goto cleanup;}usleep(1000);}
                if(!state.target_exec_observed||remozio_command_monitor_signal(monitor,SIGSTOP)||await_state(monitor,&state,1)){failure=32;goto cleanup;}
                if(remozio_command_monitor_current_job(monitor,&job)||!job.known||!job.stopped||job.traced||!job.original_group||job.stop_signal!=SIGSTOP||job.job_revision!=state.status.last_job_revision){failure=33;goto cleanup;}
                if(pty){int foreground=0;if(remozio_command_pty_foreground_group(pty,&foreground)||foreground<=0||(uint32_t)foreground!=state.status.latest.target_pid){failure=45;goto cleanup;}}
                uint64_t stopped_revision=job.job_revision;
                if(queued){
                    if(kill(state.monitor_pid,SIGSTOP)){failure=40;goto cleanup;}
                    monitor_paused=true;deadline=milliseconds()+5000;
                    struct proc_bsdinfo supervisor={0};
                    do{
                        if(proc_pidinfo(state.monitor_pid,PROC_PIDTBSDINFO,0,&supervisor,sizeof(supervisor))==sizeof(supervisor)&&supervisor.pbi_status==SSTOP)break;
                        usleep(1000);
                    }while(milliseconds()<deadline);
                    if(supervisor.pbi_status!=SSTOP){failure=41;goto cleanup;}
                }
                if(remozio_command_monitor_signal(monitor,SIGCONT)){failure=34;goto cleanup;}
                /* A pipe write is not proof that the monitor has applied this control. */
                if(!state.status.last_applied_control_sequence || remozio_command_monitor_current_job(monitor,&job)||job.known){failure=42;goto cleanup;}
                if(queued){
                    queued_checked=true;
                    if(kill(state.monitor_pid,SIGCONT)){failure=43;goto cleanup;}
                    monitor_paused=false;
                }
                deadline=milliseconds()+5000;
                do {
                    if(remozio_command_monitor_poll(monitor,&state)){failure=44;goto cleanup;}
                    if(remozio_command_monitor_current_job(monitor,&job)){failure=35;goto cleanup;}
                    if(job.known&&!job.stopped)break;
                    usleep(1000);
                }while(milliseconds()<deadline);
                /* Even after the application acknowledgment, a historical stop cannot establish current suspension. */
                if(!job.known||job.stopped||job.traced||!job.original_group||job.stop_signal||job.job_revision<stopped_revision||state.status.last_applied_control_sequence!=2){
                    fprintf(stderr,"Current-job query: known=%d stopped=%d traced=%d originalGroup=%d signal=%u oldRevision=%llu revision=%llu\n",job.known,job.stopped,job.traced,job.original_group,job.stop_signal,(unsigned long long)stopped_revision,(unsigned long long)job.job_revision);
                    failure=36;goto cleanup;
                }
                current_checked=true;
                if(remozio_command_monitor_signal(monitor,SIGKILL)){failure=37;goto cleanup;}
            }
            if(stop){if(await_state(monitor,&state,1)||!state.target_exec_observed||remozio_command_monitor_signal(monitor,SIGCONT)){failure=11;goto cleanup;}}
            if(late){uint64_t deadline=milliseconds()+8000;
                while((!state.status.failed||!state.target_exec_observed)&&milliseconds()<deadline){if(remozio_command_monitor_poll(monitor,&state)){failure=26;goto cleanup;}usleep(1000);}
                if(!state.status.failed||!state.target_exec_observed||state.monitor_reaped||state.target_exit_observed||remozio_command_monitor_signal(monitor,SIGTERM)){failure=27;goto cleanup;}
            }
        }
    }
    if(await_state(monitor,&state,2)){
        if(current){
            struct proc_bsdinfo target={0},supervisor={0};
            int target_bytes=proc_pidinfo((int)state.status.latest.target_pid,PROC_PIDTBSDINFO,0,&target,sizeof(target));
            int monitor_bytes=proc_pidinfo(state.monitor_pid,PROC_PIDTBSDINFO,0,&supervisor,sizeof(supervisor));
            fprintf(stderr,"Current-job cleanup: fault=%d protocol=%d statusClosed=%d monitorReaped=%d tag=%u targetReaped=%d wait=%u revision=%llu independentExit=%d targetBytes=%d targetState=%u targetFlags=%u monitorBytes=%d monitorState=%u\n",state.fault,state.protocol_failed,state.status_closed,state.monitor_reaped,state.status.latest.tag,state.status.reaped,state.status.latest.detail,(unsigned long long)state.status.last_job_revision,state.target_exit_observed,target_bytes,target.pbi_status,target.pbi_flags,monitor_bytes,supervisor.pbi_status);
        }
        failure=12;goto cleanup;
    }
    if(state.target_exec_observed!=(bool)(!cancel&&!immediate&&!exec_failure)||(!immediate&&(!state.status.reaped||!state.target_exit_observed))||state.monitor_ownership_lost){failure=13;goto cleanup;}
    if(!cancel&&!immediate){
        if(state.status.failed!=(exec_failure||late)||state.status.latest.detail!=(uint32_t)(current?SIGKILL:late?SIGTERM:(exec_failure?70:7)<<8)||state.monitor_wait_status!=((exec_failure||late)?70<<8:0)||!state.status.target_release_attempted||(exec_failure&&state.status.failure_error!=ENOENT)||(late&&state.status.failure_error!=EPROTO)){failure=14;goto cleanup;}
        if(!stop&&!terminal&&!exec_failure&&!late&&!current){char out[64],err[16];if(read(output[0],out,sizeof(out))!=10||memcmp(out,"OUT:unread",10)||read(error_pipe[0],err,sizeof(err))!=3||memcmp(err,"ERR",3)){failure=15;goto cleanup;}}
    }else if(!immediate){int actual=(int)state.status.latest.detail;if(state.release_attempted||state.status.target_release_attempted||(!WIFSIGNALED(actual)&&!(WIFEXITED(actual)&&WEXITSTATUS(actual)==70))){failure=16;goto cleanup;}}
    if(remozio_command_monitor_signal(monitor,SIGTERM)!=ESRCH){failure=17;goto cleanup;}
    if(current){remozio_command_current_job_t job={0};if(remozio_command_monitor_current_job(monitor,&job)||job.known){failure=38;goto cleanup;}}
cleanup:
    if(monitor){
        if(monitor_paused)(void)kill(state.monitor_pid,SIGCONT);
        (void)remozio_command_monitor_cancel(monitor);uint64_t deadline=milliseconds()+10000;
        while(!state.monitor_reaped&&!state.monitor_ownership_lost&&milliseconds()<deadline){(void)remozio_command_monitor_poll(monitor,&state);usleep(1000);}
        if(remozio_command_monitor_dispose(monitor))failure=18;
    }
    remozio_command_pty_close(pty);
    close(input[0]);close(output[0]);close(error_pipe[0]);if(output[1]>=0)close(output[1]);if(error_pipe[1]>=0)close(error_pipe[1]);if(directory>=0)close(directory);
    printf("{\"case\":\"%s\",\"failure\":%d,\"currentKernelStateChecked\":%s,\"queuedControlChecked\":%s,\"independentExec\":%s,\"independentExit\":%s,\"monitorActuallyReaped\":%s,\"targetReapedReport\":%s}\n",argv[4],failure,current_checked?"true":"false",queued_checked?"true":"false",state.target_exec_observed?"true":"false",state.target_exit_observed?"true":"false",state.monitor_reaped?"true":"false",state.status.reaped?"true":"false");
    return failure?1:0;
}
