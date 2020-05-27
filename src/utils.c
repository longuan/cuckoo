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

unsigned long getMapsItemAddr(pid_t pid, const char *str)
{
    FILE *fp;
    char filename[30];
    char line[128];
    unsigned long addr = 0;
    char perms[5];
    char *modulePath;
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL)
        exit(1);
    while (fgets(line, 128, fp) != NULL)
    {
        sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
        if (strstr(line, str) != NULL)
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

void *getTargetLibcallAddr(pid_t target_pid, const char *func_name)
{
    // mypid and mylibc_addr could be global vars.
    pid_t mypid = getpid();
    unsigned long mylibc_addr = getMapsItemAddr(mypid, "libc-");
    unsigned long myfunc_addr = getFunctionAddress(func_name);
    if (!myfunc_addr)
        return 0;
    unsigned long offset = myfunc_addr - mylibc_addr;

    unsigned long target_libcAddr = getMapsItemAddr(target_pid, "libc-");
    printf("target libc address: %lx\n", target_libcAddr);
    
    return target_libcAddr + offset;
}

int indexOfBytes(unsigned char *src, size_t src_len, unsigned char *target, size_t target_len)
{
    for(size_t i=0; i<src_len-target_len; i++)
    {
        if (src[i] == target[0])
        {
            size_t j;
            for (j = 1; j < target_len; j++)
            {
                if(target[j] != src[i+j])
                    break;
            }
            if(j == target_len)
                return i;
        }
    }
    return -1;
}