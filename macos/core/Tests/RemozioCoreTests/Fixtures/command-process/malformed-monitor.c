#include "RemozioCommandMonitorProtocol.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
int main(int argc,char **argv){
 if(argc!=3)return 64;
 unsigned char cfg[8192];while(read(3,cfg,sizeof(cfg))>0){}
 remozio_monitor_record_t record={.tag=REMOZIO_MONITOR_PREPARED,.target_pid=(uint32_t)getpid(),.sequence=1};
 unsigned char bytes[REMOZIO_MONITOR_RECORD_BYTES];if(remozio_monitor_record_encode(&record,bytes))return 65;
 size_t count=sizeof(bytes);
 if(strstr(argv[2],"bad_version")||strstr(argv[2],"blocked_bad_status"))bytes[7]=1;
 if(strstr(argv[2],"partial"))count=63;
 if(strstr(argv[2],"bad_sequence")){record.sequence=2;if(remozio_monitor_record_encode(&record,bytes))return 66;}
 if(write(5,bytes,count)!=(ssize_t)count)return 67;
 if(strstr(argv[2],"blocked_bad_status")){signal(SIGPIPE,SIG_IGN);unsigned char filler[4096]={0};while(write(5,filler,sizeof(filler))>0){}}
 close(5);char control;while(read(7,&control,1)>0){}return 0;
}
