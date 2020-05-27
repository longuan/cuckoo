
#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <errno.h>
#define oops(msg,code) do{if(errno)perror(msg);exit(code);}while(0)

enum {
    CUCKOO_OK = 0,
    CUCKOO_SYSTEM_ERROR,
    CUCKOO_RESOURCE_ERROR,
    CUCKOO_PTRACE_ERROR,
    CUCKOO_DEFAULT_ERROR
};

#define ALIGN_LEN 8
#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

#include <sys/user.h>

#include <sys/types.h>
int getNameByPid(char *name, size_t name_len, pid_t pid);

int compareMems(unsigned char *old, unsigned char *new, size_t len);
unsigned long getFunctionAddress(char* func_name);
unsigned long getMapsItemAddr(pid_t pid, const char *str);
unsigned char* findRet(void* endAddr);

int getFileSize(char *filename);

void printMem(unsigned char *data, size_t len);

void *getTargetLibcallAddr(pid_t target_pid, const char *func_name);

int indexOfBytes(unsigned char *src, size_t src_len, unsigned char *target, size_t target_len);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_H__*/
