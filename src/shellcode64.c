#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include "inject.h"
#include "shellcode.h"


static inline void setMemAndPrint(pid_t target_pid, unsigned long addr, unsigned char*data, size_t len)
{
    printMem(data, len);
    ptraceSetMems(target_pid, addr, data, len);
}

// get shellcode asm code from input file, then invoke _injectShellcode
int injectShellcode(cuckoo_context *context){
    size_t shellcode_len = getFileSize(context->injected_filename);
    if(shellcode_len == -1) return CUCKOO_RESOURCE_ERROR;
    unsigned char *shellcode = malloc(shellcode_len);
    memset(shellcode, 0, shellcode_len);

    {
        FILE *fp = fopen(context->injected_filename, "rb");
        int read_size = fread(shellcode, 1, shellcode_len, fp);
        if (read_size != shellcode_len) return CUCKOO_DEFAULT_ERROR;
        fclose(fp);
    }
    _injectShellcode(context, shellcode, shellcode_len);
    return 0;
}

int _injectShellcode(cuckoo_context *context, unsigned char *shellcode, size_t shellcode_len)
{
    pid_t target_pid = context->target_pid;
    ptraceAttach(target_pid);

    struct user_regs_struct old_regs;
    ptraceGetRegs(target_pid, &old_regs);
    printf("0x%llx\n", old_regs.rip);

    struct user_regs_struct *new_regs = (struct user_regs_struct *)malloc(sizeof(struct user_regs_struct));
    if(new_regs == NULL) oops("malloc error ", CUCKOO_SYSTEM_ERROR);
    memcpy(new_regs, &old_regs, sizeof(struct user_regs_struct));

    size_t new_len = ((shellcode_len >> 3) + 1) << 3;
    unsigned char *new_shellcode = (unsigned char *)malloc(new_len);
    memset(new_shellcode, '\x90', new_len);
    memcpy(new_shellcode, shellcode, shellcode_len);
    unsigned long shellcode_addr = getMapsItemAddr(context->target_pid, "r-x");

    setMemAndPrint(target_pid, shellcode_addr, new_shellcode, new_len);
    unsigned char buffer[new_len];
    ptraceGetMems(target_pid, shellcode_addr, buffer, new_len);
    if (compareMems(new_shellcode, buffer, new_len))
        oops("shellcode write error: ", CUCKOO_PTRACE_ERROR);
    
    
    new_regs->rip = shellcode_addr;
    printf("[+] Setting RIP to 0x%llx\n\t", new_regs->rip);
    ptraceSetRegs(target_pid, new_regs);

    ptraceDetach(target_pid);
    free(new_shellcode);
    free(new_regs);
    return CUCKOO_OK;
}
