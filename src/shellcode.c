#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include "inject.h"
#include "shellcode.h"


static void setMemAndPrint(pid_t target_pid, unsigned long addr, unsigned char*data, size_t len)
{
    for(size_t i=0; i<len; i++)
    {
        printf("0x%x ", data[i]);
    }
    printf("\n");
    ptraceSetMems(target_pid, addr, data, len);
}

int injectShellcode(cuckoo_context *context, unsigned char *shellcode, size_t shellcode_len)
{
    pid_t target_pid = context->target_pid;
    ptraceAttach(target_pid);
    
    regs_type old_regs;
    ptraceGetRegs(target_pid, &old_regs);
    printf("0x%llx\n", old_regs.rip);

    regs_type *new_regs = (regs_type *)malloc(sizeof(regs_type));
    if(new_regs == NULL) oops("malloc error ", CUCKOO_SYSTEM_ERROR);
    memcpy(new_regs, &old_regs, sizeof(regs_type));

    size_t new_len = ((shellcode_len >> 3) + 1) << 3;
    unsigned char *new_shellcode = (unsigned char *)malloc(new_len);
    memset(new_shellcode, '\x90', new_len);
    memcpy(new_shellcode, shellcode, shellcode_len);
    unsigned long shellcode_addr = getExecutableAddr(context->mem_maps)->end_addr-new_len;
    // unsigned long addr = addr_item->end_addr - new_len;

    setMemAndPrint(target_pid, shellcode_addr, new_shellcode, new_len);
    unsigned char buffer[new_len];
    ptraceGetMems(target_pid, shellcode_addr, buffer, new_len);
    if (compareMems(new_shellcode, buffer, new_len))
        oops("shellcode write error: ", CUCKOO_PTRACE_ERROR);
    
    
    new_regs->rip = shellcode_addr;
    printf("[+] Setting RIP to 0x%llx\n\t", new_regs->rip);
    ptraceSetRegs(target_pid, new_regs);
    // ptraceGetRegs(target_pid, &old_regs);
    // printf("the rip is 0x%llx\n", old_regs.rip);
    // ptraceCont(target_pid);

    ptraceDetach(target_pid);
    free(new_shellcode);
    free(new_regs);
    return CUCKOO_OK;
}
