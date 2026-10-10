#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
static int report_fd=-1;
static void continued(int number){(void)number;int saved=errno;char value='R';write(report_fd,&value,1);errno=saved;}
static int read_byte(int fd,char expected){char value=0;for(int turn=0;turn<2000;turn++){if(read(fd,&value,1)==1)return value==expected;usleep(1000);}return 0;}
static void snapshot(pid_t child,int *state,int *suspended){struct proc_bsdinfo details={0};*state=proc_pidinfo(child,PROC_PIDTBSDINFO,0,&details,sizeof(details))==sizeof(details)?(int)details.pbi_status:-1;*suspended=-1;mach_port_t name=MACH_PORT_NULL;if(task_name_for_pid(mach_task_self(),child,&name)==KERN_SUCCESS){mach_task_basic_info_data_t info={0};mach_msg_type_number_t count=MACH_TASK_BASIC_INFO_COUNT;if(task_info(name,MACH_TASK_BASIC_INFO,(task_info_t)&info,&count)==KERN_SUCCESS)*suspended=info.suspend_count;mach_port_deallocate(mach_task_self(),name);}}
static int probe(int waiting){int channel[2];if(pipe(channel))return -1;pid_t child=fork();if(child<0)return -1;int owned=1,ready=0,resumed=0,status=0,before=-1,before_suspend=-1,after=-1,after_suspend=-1;
 if(!child){close(channel[0]);if(setpgid(0,0))_exit(10);report_fd=channel[1];struct sigaction action={0};action.sa_handler=continued;sigemptyset(&action.sa_mask);if(sigaction(SIGCONT,&action,0))_exit(11);sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGCONT);if(waiting&&sigprocmask(SIG_BLOCK,&mask,0))_exit(12);char value='W';write(report_fd,&value,1);if(waiting){for(;;){int number=0;if(sigwait(&mask,&number))_exit(13);value='R';write(report_fd,&value,1);}}else{for(;;)pause();}}
 close(channel[1]);fcntl(channel[0],F_SETFL,O_NONBLOCK);ready=read_byte(channel[0],'W');if(!ready)goto cleanup;usleep(50000);if(kill(-child,SIGSTOP))goto cleanup;
 for(int turn=0;turn<2000;turn++){pid_t result=waitpid(child,&status,WNOHANG|WUNTRACED);if(result==child){if(!WIFSTOPPED(status)){owned=0;goto cleanup;}break;}if(result<0&&errno!=EINTR)goto cleanup;usleep(1000);}
 if(!WIFSTOPPED(status))goto cleanup;snapshot(child,&before,&before_suspend);if(kill(-child,SIGCONT))goto cleanup;resumed=read_byte(channel[0],'R');snapshot(child,&after,&after_suspend);
cleanup:if(owned){kill(child,SIGKILL);pid_t result;do{result=waitpid(child,&status,0);}while(result<0&&errno==EINTR);owned=result==child?0:1;}close(channel[0]);printf("{\"sigwait\":%s,\"ready\":%s,\"resumed\":%s,\"beforeBSD\":%d,\"beforeSuspendCount\":%d,\"afterBSD\":%d,\"afterSuspendCount\":%d,\"childReaped\":%s}\n",waiting?"true":"false",ready?"true":"false",resumed?"true":"false",before,before_suspend,after,after_suspend,owned?"false":"true");return !ready||!resumed||owned?1:0;}
int main(void){if(geteuid()==0)return 77;printf("{\"cases\":[");int first=probe(0);printf(",");int second=probe(1);printf("]}\n");return first||second;}
