#include "RemozioCommandMonitor.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static uint64_t now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;}
int main(int argc,char **argv){
 if(argc!=6)return 1;
 FILE *file=fopen(argv[3],"rb");if(!file)return 2;unsigned char frame[8192];size_t count=fread(frame,1,sizeof(frame),file);fclose(file);
 int input[2],output[2],errors[2];if(pipe(input)||pipe(output)||pipe(errors))return 3;
 close(input[1]);int directory=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 remozio_command_monitor_t *m=NULL;remozio_command_monitor_observation_t s={0};int failure=0,expected=atoi(argv[5]);
 int spawn_error=remozio_command_monitor_spawn(argv[1],argv[2],frame,count,input[0],output[1],errors[1],directory,&m);
 close(output[1]);close(errors[1]);
 if(!m){failure=4;goto cleanup;}
 int observed=spawn_error;uint64_t deadline=now()+8000;
 while(!observed&&now()<deadline){observed=remozio_command_monitor_poll(m,&s);usleep(1000);}
 if(observed!=expected){failure=5;goto cleanup;}
 if(remozio_command_monitor_release(m)!=expected){failure=6;goto cleanup;}
 if(remozio_command_monitor_cancel(m)){failure=7;goto cleanup;}
cleanup:
 if(m){(void)remozio_command_monitor_cancel(m);uint64_t end=now()+10000;
  do{(void)remozio_command_monitor_poll(m,&s);if(s.monitor_reaped||s.monitor_ownership_lost)break;usleep(1000);}while(now()<end);
  if(!s.monitor_reaped||s.monitor_ownership_lost||s.target_exec_observed||s.release_attempted)failure=8;
  if(remozio_command_monitor_dispose(m))failure=9;
 }
 close(input[0]);close(output[0]);close(errors[0]);close(directory);
 printf("{\"case\":\"%s\",\"failure\":%d,\"fault\":%d,\"protocolFailed\":%s,\"monitorActuallyReaped\":%s,\"targetExecObserved\":%s}\n",argv[4],failure,s.fault,s.protocol_failed?"true":"false",s.monitor_reaped?"true":"false",s.target_exec_observed?"true":"false");return failure?1:0;
}
