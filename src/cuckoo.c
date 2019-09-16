#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "utils.h"
#include "maps.h"
#include "inject.h"
#include "cuckoo.h"


static pid_t target_pid = 0;



static void cuckoo_main()
{
    ptraceAttach(target_pid);
    regs_type regs;
    ptraceGetRegs(target_pid, &regs);
    printf("0x%llx\n", regs.rip);

    // process_memory_item *list = mapsParse(target_pid);
    // print_item(list);
    // destory(list);

    wait(NULL);
    printf("[-] target process exited\n");
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
