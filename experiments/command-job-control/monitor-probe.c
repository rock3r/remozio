/* Disposable unprivileged experiment. Never embed or install this fixture. */
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/event.h>
#include <unistd.h>
static int receive(int fd,uint32_t *tag,uint32_t *detail){
 uint32_t r[3];ssize_t n=read(fd,r,sizeof r);if(n<0&&(errno==EAGAIN||errno==EINTR))return 0;
 if(n!=sizeof r||r[0]!=0x524d5431)return -1;*tag=r[1];*detail=r[2];return 1;
}
int main(int argc,char **argv){
 if(argc!=4)return 40;int cancellation=!strcmp(argv[3],"cancel"),failure=!strcmp(argv[3],"failure"),typed_stop=!strcmp(argv[3],"typed_suspend");
 remozio_command_pty_t *pty=0;int slave=-1,status[2]={-1,-1},release[2]={-1,-1};pid_t monitor=-1,target=-1;int result=1,reaped=0,observer=-1,external_exec=0,external_exit=0;
 if(remozio_command_pty_create(NULL,NULL,&pty)||remozio_command_pty_borrow_slave(pty,&slave))goto cleanup;
 struct termios raw;if(tcgetattr(slave,&raw))goto cleanup;cfmakeraw(&raw);if(typed_stop)raw.c_lflag|=ISIG;unsigned char suspend_byte=raw.c_cc[VSUSP];if(tcsetattr(slave,TCSANOW,&raw))goto cleanup;
 if(pipe(status)||pipe(release))goto cleanup;
 int copies[3]={fcntl(slave,F_DUPFD_CLOEXEC,128),fcntl(status[1],F_DUPFD_CLOEXEC,128),fcntl(release[0],F_DUPFD_CLOEXEC,128)};
 posix_spawn_file_actions_t actions;posix_spawnattr_t attributes;posix_spawn_file_actions_init(&actions);posix_spawnattr_init(&attributes);
 for(int i=0;i<3;i++)posix_spawn_file_actions_adddup2(&actions,copies[0],i);
 posix_spawn_file_actions_adddup2(&actions,copies[1],5);posix_spawn_file_actions_adddup2(&actions,copies[2],6);
 sigset_t empty,defaults;sigemptyset(&empty);sigfillset(&defaults);posix_spawnattr_setsigmask(&attributes,&empty);posix_spawnattr_setsigdefault(&attributes,&defaults);
 posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSID|POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETSIGDEF);
 char *args[]={argv[1],argv[2],NULL};char *environment[]={NULL};
 int spawned=posix_spawn(&monitor,argv[1],&actions,&attributes,args,environment);
 posix_spawnattr_destroy(&attributes);posix_spawn_file_actions_destroy(&actions);for(int i=0;i<3;i++)close(copies[i]);
 if(spawned)goto cleanup;close(status[1]);status[1]=-1;close(release[0]);release[0]=-1;remozio_command_pty_seal_slave(pty);
 fcntl(status[0],F_SETFL,O_NONBLOCK);uint32_t tag=0,detail=0;char output[100]={0};size_t used=0;bool eof=false;
 int exec_seen=0,stopped=0,stop_sent=0,continue_sent=0,failed=0,terminal=0,actual=0,kept_monitor=0;
 for(int i=0;i<5000&&!terminal;i++){
  if(observer>=0){struct kevent event;struct timespec immediate={0,0};int n=kevent(observer,NULL,0,&event,1,&immediate);if(n<0)goto cleanup;if(n==1){if(event.flags&EV_ERROR)goto cleanup;external_exec|=(event.fflags&NOTE_EXEC)!=0;external_exit|=(event.fflags&NOTE_EXIT)!=0;}}
  int got=receive(status[0],&tag,&detail);if(got<0)goto cleanup;
  if(got){
   if(tag=='R'){target=(pid_t)detail;observer=kqueue();struct kevent change;EV_SET(&change,target,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_CLEAR,NOTE_EXEC|NOTE_EXIT,0,NULL);if(observer<0||kevent(observer,&change,1,NULL,0,NULL))goto cleanup;unsigned char byte=1;if(write(release[1],&byte,1)!=1)goto cleanup;close(release[1]);release[1]=-1;}
   else if(tag=='E')exec_seen=1;
   else if(tag=='S'){
    if(detail!=SIGTSTP||target<=0)goto cleanup;stopped=1;
    int monitor_status=0;pid_t ended=waitpid(monitor,&monitor_status,WNOHANG|WUNTRACED);kept_monitor=ended==0;
    if(ended==monitor){reaped=1;goto cleanup;}
    if(remozio_command_pty_signal(pty,cancellation?SIGKILL:SIGCONT))goto cleanup;continue_sent=1;
   }
   else if(tag=='F')failed=detail==ENOENT;
   else if(tag=='X'){terminal=1;actual=(int)detail;}
   else if(tag!='C')goto cleanup;
  }
  size_t count=0;if(remozio_command_pty_read(pty,output+used,sizeof output-used,&count,&eof))goto cleanup;used+=count;
  if(!failure&&exec_seen&&used>=6&&!stop_sent){if(typed_stop){size_t sent=0;if(remozio_command_pty_write(pty,&suspend_byte,1,&sent)||sent!=1)goto cleanup;}else if(remozio_command_pty_signal(pty,SIGTSTP))goto cleanup;stop_sent=1;}
  usleep(1000);
 }
 if(!terminal)goto cleanup;
 int monitor_status=0;for(int i=0;i<1000&&!reaped;i++){
  pid_t ended=waitpid(monitor,&monitor_status,WNOHANG);if(ended==monitor)reaped=1;else if(ended<0)goto cleanup;
  size_t count=0;if(!eof&&remozio_command_pty_read(pty,output+used,sizeof output-used,&count,&eof))goto cleanup;used+=count;usleep(1000);
 }
 if(observer>=0){struct kevent event;struct timespec immediate={0,0};int n=kevent(observer,NULL,0,&event,1,&immediate);if(n<0)goto cleanup;if(n==1){if(event.flags&EV_ERROR)goto cleanup;external_exec|=(event.fflags&NOTE_EXEC)!=0;external_exit|=(event.fflags&NOTE_EXIT)!=0;}}
 if(!reaped||!WIFEXITED(monitor_status)||WEXITSTATUS(monitor_status))goto cleanup;
 int exact=failure?used==0:cancellation?(used==6&&!memcmp(output,"READY\n",6)):(used==14&&!memcmp(output,"READY\nRESUMED\n",14));
 int outcome=failure?(failed&&!exec_seen&&WIFEXITED(actual)&&WEXITSTATUS(actual)==127):cancellation?(exec_seen&&WIFSIGNALED(actual)&&WTERMSIG(actual)==SIGKILL):(exec_seen&&WIFEXITED(actual)&&WEXITSTATUS(actual)==7);
 int good=exact&&outcome&&external_exit&&(failure?!external_exec:external_exec)&&(failure||(stopped&&kept_monitor&&continue_sent));
 printf("{\"terminalSuspendByteSent\":%s,\"externalKernelExecObserved\":%s,\"externalKernelExitObserved\":%s,\"case\":\"%s\",\"defaultTSTPStopsTarget\":%s,\"monitorRemainsRunning\":%s,\"kernelExecObserved\":%s,\"execFailureReported\":%s,\"actualWaitOutcome\":%s,\"exactOutput\":%s,\"monitorReaped\":true}\n",typed_stop&&stop_sent?"true":"false",external_exec?"true":"false",external_exit?"true":"false",argv[3],stopped?"true":"false",kept_monitor?"true":"false",exec_seen?"true":"false",failed?"true":"false",outcome?"true":"false",exact?"true":"false");
 result=!good;
cleanup:
 if(monitor>0&&!reaped){
  if(release[1]>=0){close(release[1]);release[1]=-1;}
  if(pty)(void)remozio_command_pty_signal(pty,SIGKILL);
  for(int i=0;i<3000&&!reaped;i++){
   pid_t ended=waitpid(monitor,NULL,WNOHANG);
   if(ended==monitor||(ended<0&&errno==ECHILD))reaped=1;else usleep(1000);
  }
  if(!reaped){kill(monitor,SIGKILL);while(waitpid(monitor,NULL,0)<0&&errno==EINTR){}}
 }
 for(int i=0;i<2;i++){if(status[i]>=0)close(status[i]);if(release[i]>=0)close(release[i]);}
 if(observer>=0)close(observer);if(pty)remozio_command_pty_close(pty);return result;
}
