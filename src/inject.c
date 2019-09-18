#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
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
    wait(NULL);
    return CUCKOO_OK;
}

int ptraceDetach(pid_t pid)
{
    char process_name[128] = {0};
    getNameByPid(process_name, 128, pid);
    if(process_name[0] == '\0')
        oops("can't find process ", CUCKOO_DEFAULT_ERROR);
    printf("[+] detaching target process: %s\n", process_name);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return CUCKOO_OK;
}

int ptraceCont(pid_t pid)
{
    printf("[+] continue running\n");
    if((ptrace(PTRACE_CONT, pid, NULL, NULL)) < 0)
        oops("ptrace(CONT) ", CUCKOO_PTRACE_ERROR);
    return CUCKOO_OK;
}

int ptraceGetRegs(pid_t pid, regs_type *regs) 
{
    printf("[+] Getting regs\n");
    long ret = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if(ret < 0 ) oops("ptrace(GETREGS) error ", CUCKOO_PTRACE_ERROR);
    return CUCKOO_OK;
}

int ptraceSetRegs(pid_t pid, regs_type *regs)
{
    printf("[+] Setting regs\n");
    long ret = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if(ret < 0 ) oops("ptrace(SETREGS) error ", CUCKOO_PTRACE_ERROR);
    return CUCKOO_OK;
}


// the length of data must greater than sizeof(long)
int ptraceGetMems(pid_t pid, long address,unsigned char *data, size_t data_len)
{
    if(data==NULL || data_len<sizeof(long))
        return CUCKOO_RESOURCE_ERROR;

    for(size_t i=0; i<=data_len-sizeof(long); i+=sizeof(long))
    {
        long word = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
        if(word == -1 && errno) oops("ptrace(PEEKTEXT) ", CUCKOO_PTRACE_ERROR);  // errno must be checked
        memcpy(data+i, &word, sizeof(long)); 
    }
    return CUCKOO_OK;
}

