#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include "utils.h"
#include "inject.h"


static siginfo_t ptrace_getsiginfo(pid_t target)
{
    siginfo_t targetsig;
    if(ptrace(PTRACE_GETSIGINFO, target, NULL, &targetsig) == -1)
    {
        fprintf(stderr, "ptrace(PTRACE_GETSIGINFO) failed\n");
        exit(1);
    }
    return targetsig;
}

static void checktargetsig(int pid)
{
    // check the signal that the child stopped with.
    siginfo_t targetsig = ptrace_getsiginfo(pid);

    // if it wasn't SIGTRAP, then something bad happened (most likely a
    // segfault).
    if(targetsig.si_signo != SIGTRAP)
    {
        fprintf(stderr, "instead of expected SIGTRAP, target stopped with signal %d: %s\n", targetsig.si_signo, strsignal(targetsig.si_signo));
        fprintf(stderr, "sending process %d a SIGSTOP signal for debugging purposes\n", pid);
        ptrace(PTRACE_CONT, pid, NULL, SIGSTOP);
        exit(1);
    }
}

int ptraceAttach(pid_t pid)
{
    char process_name[128] = {0};
    if(getNameByPid(process_name, 128, pid)==CUCKOO_RESOURCE_ERROR)
        oops("process not exist", 1);
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
    printf("[-] detaching target process: %s\n", process_name);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return CUCKOO_OK;
}

int ptraceCont(pid_t pid)
{

    struct timespec* sleeptime = malloc(sizeof(struct timespec));

    sleeptime->tv_sec = 0;
    sleeptime->tv_nsec = 5000000;

    if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
        exit(1);
    }
    // wait(NULL);
    nanosleep(sleeptime, NULL);

    // make sure the target process received SIGTRAP after stopping.
    checktargetsig(pid);
    printf("[-] continue running\n");
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
    printf("[-] Setting regs\n");
    long ret = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if(ret < 0 ) oops("ptrace(SETREGS) error ", CUCKOO_PTRACE_ERROR);
    return CUCKOO_OK;
}


int ptraceGetMems(pid_t pid, unsigned long address,unsigned char *data, size_t data_len)
{
    // the length of data must greater than sizeof(long)
    if(data==NULL || data_len<sizeof(long))
        return CUCKOO_RESOURCE_ERROR;
    printf("[+] Getting %lu byte data from 0x%lx\n", data_len, address);
    size_t i=0;
    for(; i<data_len; i+=sizeof(long))
    {
        long word = ptrace(PTRACE_PEEKTEXT, pid, address+i, NULL);
        if(word == -1 && errno) oops("ptrace(PEEKTEXT) ", CUCKOO_PTRACE_ERROR);  // errno must be checked
        memcpy(data+i, &word, sizeof(long)); 
    }
    if(i > data_len)
    {
        size_t last_word = data_len - sizeof(long);
        long word = ptrace(PTRACE_PEEKTEXT, pid, address+last_word, NULL);
        if(word == -1 && errno) oops("ptrace(PEEKTEXT) ", CUCKOO_PTRACE_ERROR);  // errno must be checked
        memcpy(data+last_word, &word, sizeof(long));
    }
    return CUCKOO_OK;
}

int ptraceSetMems(pid_t pid, unsigned long address, unsigned char *data, size_t data_len)
{
    if(data==NULL)
        return CUCKOO_RESOURCE_ERROR;

    printf("[-] Setting %lu byte data to 0x%lx\n", data_len, address);
    size_t i=0;
    for(; i<data_len; i+=sizeof(long))
    {
        unsigned long *word = (unsigned long *)&data[i];
        long ret = ptrace(PTRACE_POKETEXT, pid, address+i, *word);
        if(ret == -1 && errno) oops("ptrace(POKETEXT) ", CUCKOO_PTRACE_ERROR);
    }
    if(i > data_len)
    {
        size_t last_word = data_len-sizeof(long);
        unsigned long *word = (unsigned long *)&data[last_word];
        ptrace(PTRACE_POKETEXT, pid, address+last_word, *word);
    }
    return CUCKOO_OK;
}
