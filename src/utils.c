#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int getNameByPid(char *name, size_t name_len, pid_t pid)
{
    char cmdline_filename[32];
    snprintf(cmdline_filename, 32, "/proc/%d/cmdline", pid);

    FILE *cmdline_file = fopen(cmdline_filename, "r");
    if(cmdline_file == NULL) return CUCKOO_RESOURCE_ERROR;
    if((fgets(name, name_len, cmdline_file)) == NULL) 
        oops("fgets error ", CUCKOO_RESOURCE_ERROR);

    return CUCKOO_OK;
}

void usage(char *prog_name)
{
    printf("Usage:\n\t%s <pid>\n", prog_name);
}


int compareMems(unsigned char *old, unsigned char *new, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if(old[i] != new[i])
            return 1;
    }
    return 0;
}