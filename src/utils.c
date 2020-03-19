#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>
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

int compareMems(unsigned char *old, unsigned char *new, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if(old[i] != new[i])
            return 1;
    }
    return 0;
}

unsigned long getFunctionAddress(char* func_name)
{
    void* libc = dlopen("libc.so.6", RTLD_LAZY);
    void* funcAddr = dlsym(libc, func_name);
    return (unsigned long)funcAddr;
}

unsigned long getLibcaddr(pid_t pid)
{
    FILE *fp;
    char filename[30];
    char line[850];
    unsigned long addr = 0;
    char perms[5];
    char* modulePath;
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL)
        exit(1);
    while(fgets(line, 850, fp) != NULL)
    {
        sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
        if(strstr(line, "libc-") != NULL)
        {
            break;
        }
    }
    fclose(fp);
    return addr;
}

unsigned char* findRet(void* endAddr)
{
    unsigned char* retInstAddr = endAddr;
    while(*retInstAddr != INTEL_RET_INSTRUCTION)
    {
        retInstAddr--;
    }
    return retInstAddr;
}


int getFileSize(char *filename)
{
    struct stat statbuf;
    int ret;
    ret = stat(filename, &statbuf);
    if (ret != 0) return -1;
    return statbuf.st_size;
}

void printMem(unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("0x%x ", data[i]);
    }
    printf("\n");
}