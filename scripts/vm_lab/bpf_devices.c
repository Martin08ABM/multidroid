/* VM-only BPF device filter, not an installed production component. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int cmd(int op, union bpf_attr *a) { return syscall(__NR_bpf,op,a,sizeof(*a)); }
static struct bpf_insn ins(unsigned char code,unsigned char dst,unsigned char src,short off,int imm) {
    return (struct bpf_insn){.code=code,.dst_reg=dst,.src_reg=src,.off=off,.imm=imm};
}
int vm_bpf_verify(int cgfd, unsigned id) {
    uint32_t ids[16]={0}; union bpf_attr a={0};
    a.query.target_fd=cgfd; a.query.attach_type=BPF_CGROUP_DEVICE; a.query.query_flags=BPF_F_QUERY_EFFECTIVE;
    a.query.prog_ids=(uintptr_t)ids; a.query.prog_cnt=16;
    if(cmd(BPF_PROG_QUERY,&a)<0) return -1;
    if(a.query.prog_cnt!=1 || ids[0]!=id) { errno=EINVAL; return -1; }
    return 0;
}
int vm_bpf_install(int cgfd,const unsigned *major,const unsigned *minor,unsigned *out_id) {
    struct bpf_insn p[20]; unsigned n=0,jumps[3];
    p[n++]=ins(BPF_LDX|BPF_W|BPF_MEM,2,1,0,0);
    p[n++]=ins(BPF_ALU64|BPF_MOV|BPF_X,3,2,0,0);
    p[n++]=ins(BPF_ALU64|BPF_AND|BPF_K,2,0,0,0xffff);
    unsigned tj=n; p[n++]=ins(BPF_JMP|BPF_JNE|BPF_K,2,0,0,BPF_DEVCG_DEV_CHAR);
    p[n++]=ins(BPF_ALU64|BPF_RSH|BPF_K,3,0,0,16);
    p[n++]=ins(BPF_ALU64|BPF_AND|BPF_K,3,0,0,~(BPF_DEVCG_ACC_READ|BPF_DEVCG_ACC_WRITE));
    unsigned mj=n; p[n++]=ins(BPF_JMP|BPF_JNE|BPF_K,3,0,0,0);
    p[n++]=ins(BPF_LDX|BPF_W|BPF_MEM,2,1,offsetof(struct bpf_cgroup_dev_ctx,major),0);
    p[n++]=ins(BPF_LDX|BPF_W|BPF_MEM,3,1,offsetof(struct bpf_cgroup_dev_ctx,minor),0);
    for(int i=0;i<3;i++) { p[n++]=ins(BPF_JMP|BPF_JNE|BPF_K,2,0,1,major[i]); jumps[i]=n; p[n++]=ins(BPF_JMP|BPF_JEQ|BPF_K,3,0,0,minor[i]); }
    unsigned deny=n; p[n++]=ins(BPF_ALU64|BPF_MOV|BPF_K,0,0,0,0); p[n++]=ins(BPF_JMP|BPF_EXIT,0,0,0,0);
    unsigned allow=n; p[n++]=ins(BPF_ALU64|BPF_MOV|BPF_K,0,0,0,1); p[n++]=ins(BPF_JMP|BPF_EXIT,0,0,0,0);
    p[tj].off=deny-tj-1; p[mj].off=deny-mj-1; for(int i=0;i<3;i++) p[jumps[i]].off=allow-jumps[i]-1;
    const char license[]="GPL"; union bpf_attr a={0};
    a.prog_type=BPF_PROG_TYPE_CGROUP_DEVICE; a.insn_cnt=n; a.insns=(uintptr_t)p; a.license=(uintptr_t)license;
    int fd=cmd(BPF_PROG_LOAD,&a); if(fd<0) return -1;
    struct bpf_prog_info info={0}; memset(&a,0,sizeof(a));
    a.info.bpf_fd=fd; a.info.info_len=sizeof(info); a.info.info=(uintptr_t)&info;
    if(cmd(BPF_OBJ_GET_INFO_BY_FD,&a)<0) { close(fd); return -1; }
    memset(&a,0,sizeof(a)); a.target_fd=cgfd; a.attach_bpf_fd=fd; a.attach_type=BPF_CGROUP_DEVICE;
    if(cmd(BPF_PROG_ATTACH,&a)<0 || vm_bpf_verify(cgfd,info.id)<0) { close(fd); return -1; }
    *out_id=info.id; return fd;
}
