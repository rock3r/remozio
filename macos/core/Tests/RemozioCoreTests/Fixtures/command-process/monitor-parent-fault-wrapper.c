#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/event.h>
#include <libproc.h>
#include <sys/proc.h>
static int test_kevent(int q,const struct kevent *c,int n,struct kevent *e,int m,const struct timespec *t) {
 static int injected=0; const char *mode=getenv("PARENT_FAULT");
 if(mode&&!strcmp(mode,"register_monitor")&&n&&!injected++){errno=EPERM;return -1;}
 if(mode&&!strcmp(mode,"target_register")&&n&&(c->fflags&NOTE_EXEC)){errno=EPERM;return -1;}
 return kevent(q,c,n,e,m,t);
}
static int test_kill(pid_t p,int s) {
 static int injected=0;const char *mode=getenv("PARENT_FAULT");
 if(mode&&!strcmp(mode,"resume_monitor")&&s==SIGCONT&&!injected++){errno=EPERM;return -1;}
 return kill(p,s);
}
static int test_proc_pidinfo(int p,int f,uint64_t a,void *b,int n) {
 const char *mode=getenv("PARENT_FAULT");
 if(mode&&!strcmp(mode,"target_metadata")){errno=ESRCH;return 0;}
 int result=proc_pidinfo(p,f,a,b,n);
 if(result==(int)sizeof(struct proc_bsdinfo)&&mode){
  struct proc_bsdinfo *value=b; static unsigned calls=0;++calls;
  if(!strcmp(mode,"target_nonchild"))value->pbi_ppid=0;
  if(!strcmp(mode,"target_birth")||(!strcmp(mode,"target_second_snapshot")&&calls==2))++value->pbi_start_tvsec;
 }
 return result;
}
#define kevent(...) test_kevent(__VA_ARGS__)
#define kill test_kill
#define proc_pidinfo test_proc_pidinfo
#include "RemozioCommandMonitor.h"
#include <sys/proc.h>
#include "CommandMonitor.c"
