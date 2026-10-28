/* VM bootstrap only: mount the one disposable disk, then exec systemd PID 1. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    if(getpid()!=1) return 1;
    if(chmod("/",0755)) { perror("root permissions"); return 1; }
    mkdir("/proc",0755); mkdir("/sys",0755); mkdir("/dev",0755); mkdir("/run",0755); mkdir("/state",0755);
    mkdir("/var",0755); mkdir("/var/lib",0755);
    if(mount("proc","/proc","proc",0,0) || mount("sysfs","/sys","sysfs",0,0) ||
       mount("devtmpfs","/dev","devtmpfs",0,0) || mount("tmpfs","/run","tmpfs",0,"mode=0755")) { perror("bootstrap mount"); return 1; }
    mkdir("/sys/fs/cgroup",0755);
    if(mount("cgroup2","/sys/fs/cgroup","cgroup2",0,0)) { perror("cgroup2"); return 1; }
    for(int i=0;i<100 && access("/dev/vda",F_OK);i++) usleep(100000);
    if(mount("/dev/vda","/var/lib","btrfs",0,0)) { perror("persistent disk"); return 1; }
    mkdir("/var/lib/vm-lab-state",0700);
    if(mount("/var/lib/vm-lab-state","/state",NULL,MS_BIND,NULL)) { perror("state bind"); return 1; }
    execl("/usr/lib/systemd/systemd","systemd","--system",(char *)0);
    perror("systemd exec"); return 1;
}
