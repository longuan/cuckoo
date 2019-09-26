#include <stdio.h>
#include "utils.h"
#include "library.h"


int injectLib(pid_t target_pid)
{
    printf("%d\n", target_pid);
    return CUCKOO_OK;
}
