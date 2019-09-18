#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "maps.h"
#include "inject.h"
#include "cuckoo.h"
#include "shellcode.h"

static pid_t target_pid = 0;

static process_memory_item *getWritableAddr(process_memory_item *list)
{
    process_memory_item *addr_item = NULL;
    while(list)
    {
        if(strchr(list->permission, 'w') != NULL) {
            addr_item = list;
            break;
        }
        list = list->next;
    }
    return addr_item;
}


static void getAndPrint(unsigned long addr, size_t len)
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

static void setAndPrint(unsigned long addr, unsigned char*data, size_t len)
{
    for(size_t i=0; i<len; i++)
    {
        printf("0x%x ", data[i]);
    }
    printf("\n");
    ptraceSetMems(target_pid, addr, data, len);
}


static void cuckoo_main()
{
    ptraceAttach(target_pid);
    
    regs_type old_regs;
    ptraceGetRegs(target_pid, &old_regs);
    printf("0x%llx\n", old_regs.rip);

    regs_type *new_regs = (regs_type *)malloc(sizeof(regs_type));
    if(new_regs == NULL) oops("malloc error ", CUCKOO_SYSTEM_ERROR);
    memcpy(new_regs, &old_regs, sizeof(regs_type));

    process_memory_item *list = mapsParse(target_pid);

    process_memory_item *addr_item = getWritableAddr(list);
    unsigned char shellcode1[] = "\xde\xad\xbe\xef\x12\x23\x34";
    size_t shellcode_len = strlen(shellcode1);
    long addr = addr_item->end_addr-shellcode_len;

    getAndPrint(addr, shellcode_len);
    setAndPrint(addr, shellcode1, shellcode_len);
    getAndPrint(addr, shellcode_len);
    
    
    // new_regs->rip = list->start_addr + 0x85f;
    // printf("[+] Setting RIP to 0x%llx\n\t", new_regs->rip);
    // ptraceSetRegs(target_pid, new_regs);

    // ptraceCont(target_pid);
    // print_item(list);


//    printf("[+] Recovery old regs\n\t");
//    ptraceSetRegs(target_pid, &old_regs);
    ptraceDetach(target_pid);
    destory(list);
    free(new_regs);
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        printf("Usage: \n\t%s <pid>\n", argv[0]);
        return 0;
    }
    
    target_pid = atoi(argv[1]);
    cuckoo_main();
    return 0;
}
