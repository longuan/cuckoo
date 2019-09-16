#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include "utils.h"
#include "inject.h"

int ptraceAttach(pid_t pid)
{
    char process_name[128] = {0};
    getNameByPid(process_name, 128, pid);
    if(process_name[0] == '\0')
        oops("can't find process ", CUCKOO_DEFAULT_ERROR);
    printf("[+] attaching target process: %s\n", process_name);
    if((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0)
        oops("ptrace(ATTACH) ", CUCKOO_PTRACE_ERROR);
    printf("[+] attach success\n");
    return CUCKOO_OK;
}

int ptraceGetRegs(pid_t pid, regs_type *regs) 
{
    printf("[+] Getting regs\n");
    long tmp = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if(tmp < 0 ) oops("ptrace(GETREGS) error ", CUCKOO_PTRACE_ERROR);
    return CUCKOO_OK;
}

int ptraceGetMems(pid_t pid, long address, char *data, size_t data_len)
{
    return CUCKOO_OK;
}
