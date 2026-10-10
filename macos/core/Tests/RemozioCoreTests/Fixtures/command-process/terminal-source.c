#include "RemozioCommandStreamSource.h"
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <sys/fileport.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
static pid_t owned_caller = -1, owned_observer = -1;
static void cleanup_child(pid_t *child) {
    if (*child <= 0) return;
    pid_t result;
    do { result = waitpid(*child, NULL, WNOHANG); } while (result < 0 && errno == EINTR);
    if (!result) {
        kill(*child, SIGKILL);
        do { result = waitpid(*child, NULL, 0); } while (result < 0 && errno == EINTR);
    }
    *child = -1;
}
static void cleanup(void) { cleanup_child(&owned_observer); cleanup_child(&owned_caller); }
static pid_t wait_owned(pid_t *child, int *status) {
    for (int attempt = 0; attempt < 5000; attempt++) {
        pid_t result = waitpid(*child, status, WNOHANG);
        if (result > 0) { *child = -1; return result; }
        if (result < 0 && errno != EINTR) return result;
        usleep(1000);
    }
    return 0;
}
typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_port_descriptor_t port; } alias_message_t;
int main(int argc, char **argv) {
    if (argc != 2) return 20;
    int flags = (int)strtol(argv[1], NULL, 10);
    bool bind_source = flags >= 0;
    if (!bind_source) flags = O_RDWR;
    signal(SIGIO, SIG_IGN);
    if (atexit(cleanup)) return 33;
    int master=-1,slave=-1,sockets[2];
    if(openpty(&master,&slave,NULL,NULL,NULL)||socketpair(AF_UNIX,SOCK_DGRAM,0,sockets))return 1;
    struct termios initial;
    if(tcgetattr(slave,&initial))return 21;
    cfmakeraw(&initial);
    if(tcsetattr(slave,TCSANOW,&initial)||write(master,"unread",6)!=6)return 22;
    mach_port_t inbox=MACH_PORT_NULL;
    if(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&inbox)!=KERN_SUCCESS||mach_port_insert_right(mach_task_self(),inbox,inbox,MACH_MSG_TYPE_MAKE_SEND)!=KERN_SUCCESS)return 10;
    mach_port_t saved_bootstrap=MACH_PORT_NULL;
    if(task_get_bootstrap_port(mach_task_self(),&saved_bootstrap)!=KERN_SUCCESS||task_set_bootstrap_port(mach_task_self(),inbox)!=KERN_SUCCESS)return 13;
    pid_t child=fork();if(child<0)return 2;
    if(child==0){
        close(master);close(sockets[0]);
        if(setsid()<0||ioctl(slave,TIOCSCTTY,0)||tcsetpgrp(slave,getpgrp()))_exit(3);
        int alias=open("/dev/tty",flags|O_NOCTTY|O_CLOEXEC);if(alias<0)_exit(4);
        int original_flags=fcntl(alias,F_GETFL),stable=-1;
        struct termios before,after;
        if(tcgetattr(alias,&before))_exit(23);
        int error=bind_source?remozio_command_stream_source_retain(alias,&stable):0;
        if(error){fprintf(stderr,"retain error=%d flags=%d\n",error,flags);_exit(24);}
        if(!bind_source)stable=fcntl(alias,F_DUPFD_CLOEXEC,3);
        bool still_alias=false;
        if(stable<0||remozio_command_stream_source_is_terminal_alias(stable,&still_alias)||still_alias==bind_source)_exit(25);
        if(fcntl(stable,F_GETFD)<0||!(fcntl(stable,F_GETFD)&FD_CLOEXEC))_exit(26);
        const int io_flags=O_ACCMODE|O_NONBLOCK|O_APPEND|O_ASYNC|O_SYNC;
        if((fcntl(stable,F_GETFL)&io_flags)!=(original_flags&io_flags))_exit(27);
        if(bind_source){
            int stable_flags=fcntl(stable,F_GETFL);
            if(fcntl(stable,F_SETFL,stable_flags^O_NONBLOCK)||fcntl(alias,F_GETFL)!=original_flags||
                fcntl(stable,F_SETFL,stable_flags))_exit(28);
        }
        if(tcgetattr(alias,&after)||memcmp(&before,&after,sizeof(before))||fcntl(alias,F_GETFL)!=original_flags)_exit(29);
        mach_port_t destination=MACH_PORT_NULL;
        if(task_get_bootstrap_port(mach_task_self(),&destination)!=KERN_SUCCESS)_exit(14);
        fileport_t fileport=MACH_PORT_NULL;
        if(fileport_makeport(stable,&fileport))_exit(11);
        alias_message_t message={0};
        message.header.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0)|MACH_MSGH_BITS_COMPLEX;
        message.header.msgh_size=sizeof(message);message.header.msgh_remote_port=destination;message.header.msgh_id=1;
        message.body.msgh_descriptor_count=1;message.port.name=fileport;message.port.disposition=MACH_MSG_TYPE_COPY_SEND;message.port.type=MACH_MSG_PORT_DESCRIPTOR;
        if(mach_msg(&message.header,MACH_SEND_MSG|MACH_SEND_TIMEOUT,sizeof(message),0,MACH_PORT_NULL,8000,MACH_PORT_NULL)!=KERN_SUCCESS)_exit(12);
        mach_port_deallocate(mach_task_self(),fileport);
        close(stable);
        mach_port_deallocate(mach_task_self(),destination);
        char payload=0;
        struct pollfd control = { .fd = sockets[1], .events = POLLIN };
        if (poll(&control, 1, 10000) <= 0 || read(sockets[1], &payload, 1) != 1) _exit(34);
        close(alias);close(slave);close(sockets[1]);_exit(0);
    }
    owned_caller = child;
    if(task_set_bootstrap_port(mach_task_self(),saved_bootstrap)!=KERN_SUCCESS)return 15;
    mach_port_deallocate(mach_task_self(),saved_bootstrap);
    close(sockets[1]);
    struct { alias_message_t message; unsigned char trailer[MAX_TRAILER_SIZE]; } received={0};
    if(mach_msg(&received.message.header,MACH_RCV_MSG|MACH_RCV_TIMEOUT,0,sizeof(received),inbox,8000,MACH_PORT_NULL)!=KERN_SUCCESS)return 6;
    if(received.message.body.msgh_descriptor_count!=1||received.message.port.type!=MACH_MSG_PORT_DESCRIPTOR)return 7;
    int alias=fileport_makefd(received.message.port.name);
    mach_port_deallocate(mach_task_self(),received.message.port.name);
    if(alias<0)return 8;
    char payload=0;
    int before=fcntl(alias,F_GETFL);
    struct stat physical_stat,alias_stat; if(fstat(slave,&physical_stat)||fstat(alias,&alias_stat))return 8;
    errno=0;pid_t physical_sid=tcgetsid(slave);int physical_error=errno;
    errno=0;pid_t alias_sid=tcgetsid(alias);int alias_error=errno;
    struct termios attributes;errno=0;int alias_tty=tcgetattr(alias,&attributes);int alias_tty_error=errno;
    struct proc_bsdinfo info={0};int info_count=proc_pidinfo(child,PROC_PIDTBSDINFO,0,&info,sizeof(info));
    bool same=physical_stat.st_dev==alias_stat.st_dev&&physical_stat.st_ino==alias_stat.st_ino&&physical_stat.st_rdev==alias_stat.st_rdev;
    printf("{\"physicalSessionMatchesCaller\":%s,\"physicalSIDError\":%d,\"aliasSessionMatchesCaller\":%s,\"aliasSIDError\":%d,\"aliasTermiosResult\":%d,\"aliasTermiosError\":%d,\"fstatIdentitiesEqual\":%s,\"kernelCallerTTYDeviceMatchesPhysical\":%s,\"aliasFlagsUnchanged\":%s}\n",physical_sid==child?"true":"false",physical_error,alias_sid==child?"true":"false",alias_error,alias_tty,alias_tty_error,same?"true":"false",info_count==sizeof(info)&&info.e_tdev==(uint32_t)physical_stat.st_rdev?"true":"false",fcntl(alias,F_GETFL)==before?"true":"false");
    fflush(stdout);
    if(bind_source && (alias_sid!=child||alias_tty||memcmp(&initial,&attributes,sizeof(initial))))return 30;
    if(bind_source && (flags&O_ACCMODE)!=O_WRONLY){
        char unread[6];
        if(read(alias,unread,sizeof(unread))!=sizeof(unread)||memcmp(unread,"unread",6))return 31;
    }
    int other_master=-1,other_slave=-1;
    if(openpty(&other_master,&other_slave,NULL,NULL,NULL))return 16;
    pid_t observer=fork();if(observer<0)return 17;
    if(observer==0){
        close(other_master);
        if(setsid()<0||ioctl(other_slave,TIOCSCTTY,0)||tcsetpgrp(other_slave,getpgrp()))_exit(18);
        errno=0;pid_t now_alias_sid=tcgetsid(alias);int now_alias_error=errno;
        errno=0;int now_attributes=tcgetattr(alias,&attributes);int now_attributes_error=errno;
        printf("{\"aliasRebindsToReceivingSession\":%s,\"aliasSIDError\":%d,\"aliasTermiosResult\":%d,\"aliasTermiosError\":%d,\"physicalSourceStillNamesOriginalCaller\":%s,\"aliasFlagsUnchanged\":%s}\n",now_alias_sid==getpid()?"true":"false",now_alias_error,now_attributes,now_attributes_error,tcgetsid(slave)==child?"true":"false",fcntl(alias,F_GETFL)==before?"true":"false");
        fflush(stdout);
        bool expected=bind_source?now_alias_sid==child:now_alias_sid==getpid();
        close(other_slave);_exit(expected && !now_attributes && tcgetsid(slave)==child ? 0 : 32);
    }
    owned_observer = observer;
    int observer_status=0;
    if(wait_owned(&owned_observer,&observer_status)!=observer||!WIFEXITED(observer_status)||WEXITSTATUS(observer_status))return 19;
    close(other_slave);close(other_master);
    payload=1;(void)write(sockets[0],&payload,1);close(sockets[0]);close(alias);close(slave);
    int status=0;if(wait_owned(&owned_caller,&status)!=child||!WIFEXITED(status)||WEXITSTATUS(status)){fprintf(stderr,"owned child status=%d\n",status);close(master);return 9;}
    close(master);
    mach_port_deallocate(mach_task_self(),inbox);
    mach_port_mod_refs(mach_task_self(),inbox,MACH_PORT_RIGHT_RECEIVE,-1);
    return 0;
}
