#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "maps.h"
#include "inject.h"
#include "cuckoo.h"


static pid_t target_pid = 0;

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

    new_regs->rip = list->start_addr + 0x85f;
    printf("[+] Setting RIP to 0x%llx\n\t", new_regs->rip);
    ptraceSetRegs(target_pid, new_regs);
    // ptraceCont(target_pid);
    // print_item(list);
    
    /*
    unsigned char data[16];
    long address = list->start_addr + 0x710;
    ptraceGetMems(target_pid, address, data, 16);
    for(int i=0; i<16; i++)
    {
        printf("0x%x ", data[i]);
    }
    printf("\n");
    */
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
