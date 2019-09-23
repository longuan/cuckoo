#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int getNameByPid(char *name, size_t name_len, pid_t pid)
{
    char cmdline_filename[32];
    snprintf(cmdline_filename, 32, "/proc/%d/cmdline", pid);

    FILE *cmdline_file = fopen(cmdline_filename, "r");
    if((fgets(name, name_len, cmdline_file)) == NULL) 
        oops("fgets error ", CUCKOO_RESOURCE_ERROR);

    return CUCKOO_OK;
}
