#include <stdio.h>
#include "utils.h"
#include "library.h"

// only works in x86 machine
int injectLib(pid_t target_pid)
{
    printf("%d\n", target_pid);
    return CUCKOO_OK;
}
