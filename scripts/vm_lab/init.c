/* Disposable VM only: no disks/network, initramfs PID 1, never host code. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <linux/bpf.h>
#include <linux/reboot.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *names[] = {"binder", "hwbinder", "vndbinder"};
static unsigned major_dev[2][3], minor_dev[2][3];
static int cgfd[2], progfd[2];
static uint32_t progid[2];
static char cgname[2][96] = {"lab0", "lab1"};

static void die(const char *s) { perror(s); puts("LAB_RESULT=FAIL"); fflush(stdout); reboot(RB_POWER_OFF); _exit(1); }
static void check(int ok, const char *s) { if (!ok) { errno = EINVAL; die(s); } }
static int bpf_cmd(int cmd, union bpf_attr *a) { return syscall(__NR_bpf, cmd, a, sizeof(*a)); }
static struct bpf_insn ins(unsigned char code, unsigned char dst, unsigned char src, short off, int imm) {
    return (struct bpf_insn){.code=code,.dst_reg=dst,.src_reg=src,.off=off,.imm=imm};
}
static int load_filter(int which) {
    struct bpf_insn p[20]; unsigned n=0, jumps[3];
    p[n++]=ins(BPF_LDX|BPF_W|BPF_MEM, 2, 1, 0, 0);
    p[n++]=ins(BPF_ALU64|BPF_MOV|BPF_X, 3, 2, 0, 0);
    p[n++]=ins(BPF_ALU64|BPF_AND|BPF_K, 2, 0, 0, 0xffff);
    unsigned type_jump=n; p[n++]=ins(BPF_JMP|BPF_JNE|BPF_K, 2, 0, 0, BPF_DEVCG_DEV_CHAR);
    p[n++]=ins(BPF_ALU64|BPF_RSH|BPF_K, 3, 0, 0, 16);
    p[n++]=ins(BPF_ALU64|BPF_AND|BPF_K, 3, 0, 0, ~(BPF_DEVCG_ACC_READ|BPF_DEVCG_ACC_WRITE));
    unsigned mode_jump=n; p[n++]=ins(BPF_JMP|BPF_JNE|BPF_K, 3, 0, 0, 0);
    p[n++]=ins(BPF_LDX|BPF_W|BPF_MEM, 2, 1, offsetof(struct bpf_cgroup_dev_ctx, major), 0);
    p[n++]=ins(BPF_LDX|BPF_W|BPF_MEM, 3, 1, offsetof(struct bpf_cgroup_dev_ctx, minor), 0);
    for (int i=0; i<3; i++) {
        p[n++]=ins(BPF_JMP|BPF_JNE|BPF_K, 2, 0, 1, major_dev[which][i]);
        jumps[i]=n; p[n++]=ins(BPF_JMP|BPF_JEQ|BPF_K, 3, 0, 0, minor_dev[which][i]);
    }
    unsigned deny=n; p[n++]=ins(BPF_ALU64|BPF_MOV|BPF_K, 0, 0, 0, 0);
    p[n++]=ins(BPF_JMP|BPF_EXIT, 0, 0, 0, 0);
    unsigned allow=n; p[n++]=ins(BPF_ALU64|BPF_MOV|BPF_K, 0, 0, 0, 1);
    p[n++]=ins(BPF_JMP|BPF_EXIT, 0, 0, 0, 0);
    p[type_jump].off=deny-type_jump-1; p[mode_jump].off=deny-mode_jump-1;
    for (int i=0;i<3;i++) p[jumps[i]].off=allow-jumps[i]-1;
    char log[65536]={0}; const char license[]="GPL";
    union bpf_attr a={0}; a.prog_type=BPF_PROG_TYPE_CGROUP_DEVICE; a.insn_cnt=n;
    a.insns=(uintptr_t)p; a.license=(uintptr_t)license;
    a.log_buf=(uintptr_t)log; a.log_size=sizeof(log); a.log_level=1;
    int fd=bpf_cmd(BPF_PROG_LOAD,&a);
    if (fd<0) { fprintf(stderr,"BPF verifier: %s\n",log); return -1; }
    struct bpf_prog_info info={0}; memset(&a,0,sizeof(a));
    a.info.bpf_fd=fd; a.info.info_len=sizeof(info); a.info.info=(uintptr_t)&info;
    if (bpf_cmd(BPF_OBJ_GET_INFO_BY_FD,&a)<0) { close(fd); return -1; }
    progid[which]=info.id; return fd;
}
static int query_result(int i) {
    uint32_t ids[8]={0}; union bpf_attr a={0};
    a.query.target_fd=cgfd[i]; a.query.attach_type=BPF_CGROUP_DEVICE;
    a.query.query_flags=BPF_F_QUERY_EFFECTIVE; a.query.prog_cnt=8; a.query.prog_ids=(uintptr_t)ids;
    if (bpf_cmd(BPF_PROG_QUERY,&a)<0) return -1;
    if(a.query.prog_cnt!=1 || ids[0]!=progid[i]) { errno=EINVAL; return -1; }
    return 0;
}
static void query(int i) { if(query_result(i)<0) die("BPF_PROG_QUERY or identity mismatch"); }
static int move_result(int i, pid_t pid) {
    char path[160], value[40]; snprintf(path,sizeof(path),"/cg/%s/cgroup.procs",cgname[i]);
    int fd=open(path,O_WRONLY|O_CLOEXEC); if(fd<0) return -1;
    int n=snprintf(value,sizeof(value),"%ld",(long)pid);
    int ok=write(fd,value,n)==n; int saved=errno;
    close(fd); errno=saved; return ok?0:-1;
}
static void move_process(int i,pid_t pid) { if(move_result(i,pid)<0) die("move cgroup"); }
static int access_nodes(int own) {
    char path[80]; int ok=1;
    for(int i=0;i<2;i++) for(int n=0;n<4;n++) {
        snprintf(path,sizeof(path),"/%c/%s",'a'+i,n<3?names[n]:"binder-control");
        errno=0; int fd=open(path,O_RDWR|O_CLOEXEC); int err=errno;
        int expected=(i==own && n<3);
        if(expected && fd>=0) { struct binder_version v={0}; if(ioctl(fd,BINDER_VERSION,&v)<0 || !v.protocol_version) ok=0; }
        else if(expected || fd>=0 || err!=EPERM) ok=0;
        printf("helper=%d path=%s expected=%s result=%s errno=%d\n",own,path,expected?"allow":"deny",fd>=0?"open":"error",err);
        if(fd>=0) close(fd);
    }
    fflush(stdout); return ok;
}
struct worker { pid_t pid; int cmd, result; };
static struct worker start_worker(int i) {
    int control[2], result[2]; if(pipe(control)||pipe(result)) die("pipe");
    pid_t pid=fork(); if(pid<0) die("fork");
    if(pid==0) {
        close(control[1]); close(result[0]); char c;
        /* Do not retain a previous worker's control pipe or BPF descriptors. */
        for(int fd=3;fd<1024;fd++) if(fd!=control[0] && fd!=result[1]) close(fd);
        if(read(control[0],&c,1)!=1 || c!='G') _exit(10);
        errno=0;
        if(mknod("/mknod-denied",S_IFCHR|0600,makedev(major_dev[i][0],minor_dev[i][0]))==0 || errno!=EPERM) _exit(13);
        printf("helper=%d MKNOD_DENIED=EPERM (uid=0)\n",i);
        if(setgid(1000)||setuid(1000)) _exit(11);
        c=access_nodes(i)?'P':'F'; if(write(result[1],&c,1)!=1) _exit(12);
        while(read(control[0],&c,1)==1 && c=='R') { c=access_nodes(i)?'P':'F'; if(write(result[1],&c,1)!=1) _exit(14); }
        _exit(0);
    }
    close(control[0]); close(result[1]); move_process(i,pid); query(i);
    if(write(control[1],"G",1)!=1) die("release worker");
    return (struct worker){pid,control[1],result[0]};
}
static void expect_worker(struct worker w) { char c; check(read(w.result,&c,1)==1 && c=='P',"worker failed"); }
static void failed_gate_test(int stage) {
    int go[2], marker[2]; if(pipe(go)||pipe(marker)) die("pipe");
    pid_t p=fork(); if(p<0) die("fork");
    if(!p) { close(go[1]); close(marker[0]); char c; if(read(go[0],&c,1)==1 && c=='G') write(marker[1],"X",1); _exit(0); }
    close(go[0]); close(marker[1]); union bpf_attr a={0}; int rc;
    if(stage==0) { a.prog_type=BPF_PROG_TYPE_CGROUP_DEVICE; rc=bpf_cmd(BPF_PROG_LOAD,&a); }
    else if(stage==1) { a.target_fd=-1; a.attach_bpf_fd=progfd[0]; a.attach_type=BPF_CGROUP_DEVICE; rc=bpf_cmd(BPF_PROG_ATTACH,&a); }
    else if(stage==2) { a.query.target_fd=-1; a.query.attach_type=BPF_CGROUP_DEVICE; rc=bpf_cmd(BPF_PROG_QUERY,&a); }
    else rc=open("/cg/nonexistent-lab/cgroup.procs",O_WRONLY|O_CLOEXEC);
    check(rc<0,"injected gate operation must fail"); close(go[1]);
    char c; check(read(marker[0],&c,1)==0,"worker released after attach failure");
    close(marker[0]); int status; waitpid(p,&status,0); check(WIFEXITED(status) && WEXITSTATUS(status)==0,"failure worker");
    printf("FAILED_GATE_STAGE_%d=PASS\n",stage);
}
#ifdef LAB_REAL_HELPER
#ifdef LAB_STORE_TEST
static int bridge(const char *action,int index,pid_t pid) {
    pid_t p=fork(); if(p<0) return -1;
    if(!p) {
        char idx[8], number[24]; snprintf(idx,sizeof(idx),"%d",index); snprintf(number,sizeof(number),"%ld",(long)pid);
        char *args[]={"/usr/bin/python3","-B","/lab/store_bridge.py",(char *)action,idx,number,NULL};
        execv(args[0],args); _exit(90);
    }
    int status; if(waitpid(p,&status,0)!=p || !WIFEXITED(status) || WEXITSTATUS(status)) return -1;
    return 0;
}
static void read_group_name(int i) {
    char path[48]; snprintf(path,sizeof(path),"/vmbridge/cgname%d",i);
    FILE *file=fopen(path,"r"); if(!file) die("read journal group name");
    if(!fgets(cgname[i],sizeof(cgname[i]),file)) die("read journal group");
    fclose(file); cgname[i][strcspn(cgname[i],"\n")]=0;
    check(strlen(cgname[i])==68 && !strncmp(cgname[i],"wm-",3) && cgname[i][35]=='-',"invalid journal group name");
    for(int j=3;j<68;j++) if(j!=35)
        check((cgname[i][j]>='0' && cgname[i][j]<='9') || (cgname[i][j]>='a' && cgname[i][j]<='f'),"invalid journal group component");
}
#endif
struct real_worker { pid_t pid; int control; FILE *output; int index; };
static int pause_stage=-1, notify_fd=-1;
static void checkpoint(int stage,pid_t worker) {
    if(stage!=pause_stage) return;
    if(write(notify_fd,&worker,sizeof(worker))!=sizeof(worker)) _exit(30);
    raise(SIGSTOP);
}
static void remove_real_group(int i) {
#ifdef LAB_STORE_TEST
    if(bridge("verify",i,0)) die("refusing unverified cgroup removal");
#endif
    if(progfd[i]>=0) { close(progfd[i]); progfd[i]=-1; }
    if(cgfd[i]>=0) { close(cgfd[i]); cgfd[i]=-1; }
    char path[120]; snprintf(path,sizeof(path),"/cg/%s",cgname[i]);
    if(rmdir(path)) die("remove helper cgroup");
}
static void remove_real_sandbox(int i) {
    char path[32]; snprintf(path,sizeof(path),"/sandbox%d",i);
    if(rmdir(path)) die("remove helper sandbox");
}
/* VM-only launcher. A child blocks until policy, migration and query succeed. */
static struct real_worker start_real(int i, int fault) {
#ifdef LAB_STORE_TEST
    if(bridge("prepare",i,0)) die("prepare helper journal");
    read_group_name(i);
#endif
    int gate[2], control[2], output[2];
    if(pipe2(gate,O_CLOEXEC)||pipe2(control,O_CLOEXEC)||pipe2(output,O_CLOEXEC)) die("helper pipes");
    char path[24]; snprintf(path,sizeof(path),"/%c",'a'+i);
    int binder=open(path,O_RDONLY|O_DIRECTORY); if(binder<0) die("open Binder directory");
    char sandbox[24]; snprintf(sandbox,sizeof(sandbox),"/sandbox%d",i);
    if(mkdir(sandbox,0700)) die("helper sandbox");
    pid_t pid=fork(); if(pid<0) die("fork real helper");
    if(pid==0) {
        close(gate[1]); close(control[1]); close(output[0]);
        if(dup2(control[0],0)<0 || dup2(output[1],1)<0) _exit(20);
        for(int fd=3;fd<1024;fd++) if(fd!=gate[0] && fd!=binder) close(fd);
        char c; if(read(gate[0],&c,1)!=1 || c!='G') _exit(21);
        close(gate[0]);
        char fdarg[16], idarg[16]; snprintf(fdarg,sizeof(fdarg),"%d",binder); snprintf(idarg,sizeof(idarg),"%d",1000+i);
        char *args[]={"/usr/bin/python3","-B","-I","/lab/hold_helper.py",fdarg,idarg,idarg,sandbox,NULL};
        execv(args[0],args); _exit(22);
    }
    close(gate[0]); close(control[0]); close(output[1]); close(binder);
    checkpoint(0,pid);
    char cgpath[120]; snprintf(cgpath,sizeof(cgpath),"/cg/%s",cgname[i]);
    if(mkdir(cgpath,0755)) die("create helper cgroup");
    cgfd[i]=open(cgpath,O_RDONLY|O_DIRECTORY|O_CLOEXEC); progfd[i]=-1;
    if(cgfd[i]<0) goto failed;
#ifdef LAB_STORE_TEST
    checkpoint(5,pid);
    if(bridge("record",i,0)) goto failed;
#endif
    checkpoint(1,pid);
    if(fault==0) { union bpf_attr bad={0}; bad.prog_type=BPF_PROG_TYPE_CGROUP_DEVICE; if(bpf_cmd(BPF_PROG_LOAD,&bad)>=0) die("load injection"); goto failed; }
    progfd[i]=load_filter(i); if(progfd[i]<0) goto failed;
    checkpoint(2,pid);
    union bpf_attr a={0}; a.target_fd=fault==1?-1:cgfd[i]; a.attach_bpf_fd=progfd[i]; a.attach_type=BPF_CGROUP_DEVICE;
    if(bpf_cmd(BPF_PROG_ATTACH,&a)<0) goto failed;
    checkpoint(3,pid);
    if(fault==2) { union bpf_attr bad={0}; bad.query.target_fd=-1; bad.query.attach_type=BPF_CGROUP_DEVICE; if(bpf_cmd(BPF_PROG_QUERY,&bad)>=0) die("query injection"); goto failed; }
    if(query_result(i)<0) goto failed;
    if(fault==3) { int bad=open("/cg/nonexistent-lab/cgroup.procs",O_WRONLY); if(bad>=0) die("move injection"); goto failed; }
    if(move_result(i,pid)<0 || query_result(i)<0) goto failed;
#ifdef LAB_STORE_TEST
    if(bridge("process",i,pid)) goto failed;
#endif
    checkpoint(4,pid);
    if(fault==4) goto failed;
    if(write(gate[1],"G",1)!=1) goto failed;
    close(gate[1]);
    FILE *out=fdopen(output[0],"r"); if(!out) die("fdopen helper");
    return (struct real_worker){pid,control[1],out,i};
failed:
    close(gate[1]); close(control[1]);
    int status; if(waitpid(pid,&status,0)!=pid) die("wait failed helper");
    char c; check(read(output[0],&c,1)==0,"helper ran after failed isolation"); close(output[0]);
    remove_real_group(i); remove_real_sandbox(i);
#ifdef LAB_STORE_TEST
    if(bridge("clear",i,0)) die("clear failed helper journals");
#endif
    if(fault<0) die("helper setup failed closed");
    printf("REAL_HELPER_FAILED_STAGE_%d=PASS\n",fault);
    return (struct real_worker){-1,-1,NULL,i};
}
static void helper_line(struct real_worker w, const char *expected) {
    char line[4096];
    if(expected[0]=='{') {
        check(fgets(line,sizeof(line),w.output)!=NULL && strstr(line,"REAL_HELPER_ACCESS=PASS"),"helper cgroup access");
        printf("REAL_HELPER: %s",line);
    }
    check(fgets(line,sizeof(line),w.output)!=NULL,"helper output");
    printf("REAL_HELPER: %s",line); check(strstr(line,expected)!=NULL,"unexpected helper response");
    if(expected[0]=='{') check(strstr(line,"\"gbinder\": true") && strstr(line,"\"privileges_dropped\": true") &&
                               strstr(line,"\"control_visible\": false") && strstr(line,"\"host_etc_visible\": false"),"helper isolation result");
    if(expected[0]=='{') for(int n=0;n<3;n++) {
        char device[80]; snprintf(device,sizeof(device),"\"major\": %u, \"minor\": %u, \"protocol\":",major_dev[w.index][n],minor_dev[w.index][n]);
        check(strstr(line,device)!=NULL,"wrong helper Binder device");
    }
}
static void stop_real(struct real_worker w) {
    check(write(w.control,"quit\n",5)==5,"quit helper"); close(w.control);
    int status; check(waitpid(w.pid,&status,0)==w.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"helper exit");
    fclose(w.output); remove_real_group(w.index); remove_real_sandbox(w.index);
#ifdef LAB_STORE_TEST
    if(bridge("clear",w.index,0)) die("clear stopped helper journals");
#endif
}
static void test_interruptions(void) {
    int stages=5;
#ifdef LAB_STORE_TEST
    stages=6;
#endif
    for(int stage=0;stage<stages;stage++) {
        int notification[2]; if(pipe(notification)) die("interruption pipe");
        pid_t supervisor=fork(); if(supervisor<0) die("fork supervisor");
        if(supervisor==0) {
            close(notification[0]); notify_fd=notification[1]; pause_stage=stage;
            start_real(0,-1); _exit(31);
        }
        close(notification[1]); pid_t helper;
        check(read(notification[0],&helper,sizeof(helper))==sizeof(helper),"checkpoint notification");
        close(notification[0]); int status;
        check(waitpid(supervisor,&status,WUNTRACED)==supervisor && WIFSTOPPED(status),"supervisor checkpoint");
        if(kill(supervisor,SIGKILL)) die("kill supervisor");
        check(waitpid(supervisor,&status,0)==supervisor && WIFSIGNALED(status),"supervisor terminated");
        check(waitpid(helper,&status,0)==helper && WIFEXITED(status) && WEXITSTATUS(status)==21,"orphan helper did not fail closed");
#ifdef LAB_STORE_TEST
        read_group_name(0);
#endif
        char path[120]; snprintf(path,sizeof(path),"/cg/%s",cgname[0]);
        if(stage>0) {
#ifdef LAB_STORE_TEST
            if(bridge("verify",0,0)) {
                check(stage==5 && access(path,F_OK)==0,"ambiguous cgroup not preserved");
                puts("VM_AMBIGUOUS_CGROUP_PRESERVED=PASS");
                /* The fixture alone knows it created this empty cgroup. */
            }
#endif
            if(rmdir(path)) die("recover interrupted cgroup");
        }
        remove_real_sandbox(0);
#ifdef LAB_STORE_TEST
        if(bridge("clear",0,0)) die("clear interrupted helper journals");
#endif
        puts("INTERRUPTED_SUPERVISOR=PASS");
    }
    int notification[2]; if(pipe(notification)) die("running interruption pipe");
    pid_t supervisor=fork(); if(supervisor<0) die("fork running supervisor");
    if(supervisor==0) {
        close(notification[0]); struct real_worker w=start_real(0,-1); helper_line(w,"{");
        if(write(notification[1],&w.pid,sizeof(w.pid))!=sizeof(w.pid)) _exit(32);
        raise(SIGSTOP); _exit(33);
    }
    close(notification[1]); pid_t helper;
    check(read(notification[0],&helper,sizeof(helper))==sizeof(helper),"running checkpoint"); close(notification[0]);
    int status; check(waitpid(supervisor,&status,WUNTRACED)==supervisor && WIFSTOPPED(status),"running stop");
    if(kill(supervisor,SIGKILL)) die("kill running supervisor");
    check(waitpid(supervisor,&status,0)==supervisor && WIFSIGNALED(status),"running supervisor killed");
    check(waitpid(helper,&status,0)==helper && WIFEXITED(status) && WEXITSTATUS(status)==0,"running helper did not exit on EOF");
#ifdef LAB_STORE_TEST
    read_group_name(0);
#endif
    char path[120]; snprintf(path,sizeof(path),"/cg/%s",cgname[0]);
#ifdef LAB_STORE_TEST
    if(bridge("verify",0,0)) die("refusing unverified running cgroup removal");
#endif
    if(rmdir(path)) die("recover running cgroup");
    remove_real_sandbox(0);
#ifdef LAB_STORE_TEST
    if(bridge("clear",0,0)) die("clear running helper journals");
#endif
    puts("INTERRUPTED_RUNNING_SUPERVISOR=PASS");
}
#ifdef LAB_STORE_TEST
static void test_foreign_cgroup(void) {
    if(bridge("prepare",0,0)) die("foreign test prepare");
    read_group_name(0);
    char path[120]; snprintf(path,sizeof(path),"/cg/%s",cgname[0]);
    if(mkdir(path,0755) || bridge("record",0,0)) die("foreign test record");
    if(rmdir(path) || mkdir(path,0755)) die("foreign test replace");
    check(bridge("verify",0,0)!=0 && access(path,F_OK)==0,"replacement was not preserved");
    puts("VM_FOREIGN_CGROUP_PRESERVED=PASS");
    /* The fixture created the replacement and removes it only inside the VM. */
    if(rmdir(path) || bridge("clear",0,0)) die("foreign test teardown");
}
#endif
static void test_real_helpers(void) {
    struct real_worker b=start_real(1,-1); helper_line(b,"{");
    for(int stage=0;stage<5;stage++) start_real(0,stage);
    test_interruptions();
#ifdef LAB_STORE_TEST
    test_foreign_cgroup();
    if(bridge("blocked",1,0)) die("instance B Binder guard");
#endif
    query(1); check(write(b.control,"check\n",6)==6,"check B after failures"); helper_line(b,"HELPER_CHECK=PASS");
    struct real_worker a=start_real(0,-1); helper_line(a,"{");
    stop_real(a);
    query(1);
    check(write(b.control,"check\n",6)==6,"check B"); helper_line(b,"HELPER_CHECK=PASS");
    a=start_real(0,-1); helper_line(a,"{");
    check(write(b.control,"check\n",6)==6,"check B after restart"); helper_line(b,"HELPER_CHECK=PASS");
    stop_real(a); stop_real(b); puts("REAL_GBINDER_SUPERVISION=PASS");
#ifdef LAB_STORE_TEST
    puts("VM_JOURNALED_SUPERVISION=PASS");
#endif
}
#endif
#ifdef LAB_STORE_TEST
static void test_protected_store(void) {
    if(mkdir("/vmprobe",0700)) die("store probe directory");
    pid_t pid=fork(); if(pid<0) die("store probe fork");
    if(pid==0) {
        char *args[]={"/usr/bin/python3","-B","/lab/project/scripts/probe_privileged.py","--vm-child","/vmprobe",NULL};
        execv(args[0],args); _exit(70);
    }
    int status; check(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"ProtectedStore VM probe");
    puts("VM_PROTECTED_STORE=PASS");
}
#endif
int main(void) {
    if(getpid()!=1) { fprintf(stderr,"VM init must run as PID 1\n"); return 1; }
    setvbuf(stdout,NULL,_IONBF,0); puts("WAYDROID_BPF_VM_LAB=START");
    mkdir("/proc",0755); mkdir("/sys",0755); mkdir("/cg",0755); mkdir("/a",0755); mkdir("/b",0755);
    if(mount("proc","/proc","proc",0,NULL)||mount("sysfs","/sys","sysfs",0,NULL)||mount("cgroup2","/cg","cgroup2",0,NULL)) die("mount kernel filesystems");
#ifdef LAB_STORE_TEST
    if(bridge("setup",0,0)) die("setup protected store");
    FILE *ids=fopen("/vmbridge/ids","r"); if(!ids) die("read store instance ids");
    for(int i=0;i<2;i++) {
        char id[40], source[96], target[8];
        if(!fgets(id,sizeof(id),ids)) die("read store id");
        id[strcspn(id,"\n")]=0; check(strlen(id)==32,"invalid store id");
        snprintf(source,sizeof(source),"/vmbridge/binders/%s",id);
        snprintf(target,sizeof(target),"/%c",'a'+i);
        if(mount(source,target,NULL,MS_BIND,NULL)) die("bind store Binder for laboratory");
    }
    fclose(ids);
#else
    if(mount("lab-a","/a","binder",0,NULL)||mount("lab-b","/b","binder",0,NULL)) die("mount binderfs");
#endif
    for(int i=0;i<2;i++) {
        char path[80]; snprintf(path,sizeof(path),"/%c",'a'+i); if(chmod(path,0755)) die("chmod binderfs");
        for(int n=0;n<4;n++) {
            snprintf(path,sizeof(path),"/%c/%s",'a'+i,n<3?names[n]:"binder-control"); struct stat s;
            if(stat(path,&s)||!S_ISCHR(s.st_mode)||chmod(path,0666)) die("binder node");
            if(n<3) { major_dev[i][n]=major(s.st_rdev); minor_dev[i][n]=minor(s.st_rdev); }
            printf("DEVICE %s %u:%u\n",path,major(s.st_rdev),minor(s.st_rdev));
        }
        snprintf(path,sizeof(path),"/cg/lab%d",i); if(mkdir(path,0755)) die("mkdir cgroup");
        cgfd[i]=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); if(cgfd[i]<0) die("open cgroup");
        progfd[i]=load_filter(i); if(progfd[i]<0) die("load BPF");
        union bpf_attr a={0}; a.target_fd=cgfd[i]; a.attach_bpf_fd=progfd[i]; a.attach_type=BPF_CGROUP_DEVICE;
        if(bpf_cmd(BPF_PROG_ATTACH,&a)<0) die("BPF_PROG_ATTACH");
        query(i);
    }
    if(mknod("/mknod-baseline",S_IFCHR|0600,makedev(major_dev[0][0],minor_dev[0][0])) || unlink("/mknod-baseline")) die("baseline mknod");
    puts("MKNOD_BASELINE=PASS");
    for(int stage=0;stage<4;stage++) failed_gate_test(stage);
    struct worker a=start_worker(0), b=start_worker(1); expect_worker(a); expect_worker(b);
    close(a.cmd); int status; waitpid(a.pid,&status,0); check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"stop A");
    if(write(b.cmd,"R",1)!=1) die("restart test B");
    expect_worker(b);
    struct worker a2=start_worker(0); expect_worker(a2);
    if(write(b.cmd,"R",1)!=1) die("test B after restart A");
    expect_worker(b); close(a2.cmd); waitpid(a2.pid,&status,0);
    check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"stop restarted A");
    close(b.cmd); waitpid(b.pid,&status,0);
    check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"stop B");
#ifdef LAB_REAL_HELPER
#ifdef LAB_STORE_TEST
    for(int i=0;i<2;i++) {
        close(progfd[i]); close(cgfd[i]); progfd[i]=cgfd[i]=-1;
        char path[120]; snprintf(path,sizeof(path),"/cg/%s",cgname[i]);
        if(rmdir(path)) die("remove original test cgroup");
    }
#else
    for(int i=0;i<2;i++) remove_real_group(i);
#endif
    test_real_helpers();
#endif
#ifdef LAB_STORE_TEST
    test_protected_store();
#endif
    puts("LAB_RESULT=PASS");
    sync(); reboot(RB_POWER_OFF); return 0;
}
