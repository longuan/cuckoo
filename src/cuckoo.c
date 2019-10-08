#include "cuckoo.h"
#include "shellcode.h"


void init_context(cuckoo_context *context, pid_t target_pid)
{
    context->target_pid = target_pid;
    context->mem_maps = mapsParse(target_pid);
    context->inject_type = 0; // not used
}


void clean(cuckoo_context *context)
{
    destoryList(context->mem_maps);
}


