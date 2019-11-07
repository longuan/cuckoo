#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include "inject.h"
#include "shellcode.h"


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

    unsigned long shellcode_addr = getExecutableItem(context->mem_maps)->end_addr-shellcode_len;
    // unsigned long addr = addr_item->end_addr - new_len;

    ptraceSetMems(target_pid, shellcode_addr, shellcode, shellcode_len);
    printMem(shellcode, shellcode_len);
    unsigned char buffer[shellcode_len];
    ptraceGetMems(target_pid, shellcode_addr, buffer, shellcode_len);
    if (compareMems(shellcode, buffer, shellcode_len))
        oops("shellcode write error: ", CUCKOO_PTRACE_ERROR);
    
    
    new_regs->rip = shellcode_addr;
    printf("[+] Setting RIP to 0x%llx\n\t", new_regs->rip);
    ptraceSetRegs(target_pid, new_regs);

    ptraceDetach(target_pid);
    free(new_regs);
    return CUCKOO_OK;
}
