#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include "maps.h"
#include "cuckoo.h"

typedef struct user_regs_struct regs_type;

static pid_t target_pid = 0;

void getRegs(regs_type *regs) 
{
    printf("[+] Getting regs\n");
    long tmp = ptrace(PTRACE_GETREGS, target_pid, NULL, regs);
    if(tmp < 0 )
    {
        perror("ptrace(GETREGS):");
        exit(1);
    }
}


void cuckoo_main()
{
    printf("[+] attaching target process %d\n", target_pid);
    if((ptrace(PTRACE_ATTACH, target_pid, NULL, NULL)) < 0)
    {
        perror("ptrace(ATTACH):");
        exit(1);
    }
    printf("[+] attach success\n");

    regs_type regs;
    getRegs(&regs);
    // printf("0x%x\n", regs.rip);


    wait(NULL);
    printf("[-] target process exited\n");
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        printf("Usage: \n\t%s <pid>\n", argv[0]);
        return 0;
    }
    
    target_pid = atoi(argv[1]);
    process_memory_item *list = mapsParse(target_pid);
    print_item(list);
    destory(list);
    return 0;
}
