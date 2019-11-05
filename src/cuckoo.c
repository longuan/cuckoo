#include "cuckoo.h"
#include "utils.h"


int init_context(cuckoo_context *context, pid_t target_pid)
{
    context->target_pid = target_pid;
    context->mem_maps = mapsParse(target_pid);
    if(context->mem_maps == NULL)
        return CUCKOO_RESOURCE_ERROR;
    context->inject_type = 0; // not used
    return CUCKOO_OK;
}


void clean_context(cuckoo_context *context)
{
    destoryList(context->mem_maps);
}


