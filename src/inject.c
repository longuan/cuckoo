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
int ptraceGetMems(pid_t pid, unsigned long address,unsigned char *data, size_t data_len)
{
    if(data==NULL || data_len<sizeof(long))
        return CUCKOO_RESOURCE_ERROR;
    printf("[+] Getting %lu byte data from 0x%lx\n", data_len, address);
    for(size_t i=0; i<=data_len-sizeof(long); i+=sizeof(long))
    {
        long word = ptrace(PTRACE_PEEKTEXT, pid, address+i, NULL);
        if(word == -1 && errno) oops("ptrace(PEEKTEXT) ", CUCKOO_PTRACE_ERROR);  // errno must be checked
        memcpy(data+i, &word, sizeof(long)); 
    }
    return CUCKOO_OK;
}

int ptraceSetMems(pid_t pid, unsigned long address, unsigned char *data, size_t data_len)
{
    if(data==NULL)
        return CUCKOO_RESOURCE_ERROR;
    /*
    unsigned char *new_data=NULL;
    if(data_len%sizeof(long) != 0)
    {
        size_t new_len = lengthAlign(data_len);
        new_data = (unsigned char *)malloc(new_len);
        memcpy(new_data, data, data_len);
        printf("[+] align data with %lu '\\x90'\n", new_len-data_len);
        for(size_t i=data_len; i<new_len; i++)
            new_data[i] = '\x90';
        data = new_data;
        address = address + data_len - new_len;
        data_len = new_len;
    }
    */
    printf("[+] Setting %lu byte data to 0x%lx\n", data_len, address);
    for(size_t i=0; i<data_len; i+=sizeof(long))
    {
        unsigned long *word = (unsigned long *)&data[i];
        long ret = ptrace(PTRACE_POKETEXT, pid, address+i, *word);
        if(ret == -1 && errno) oops("ptrace(POKETEXT) ", CUCKOO_PTRACE_ERROR);
    }
    // if(new_data) free(new_data);
    return CUCKOO_OK;
}
