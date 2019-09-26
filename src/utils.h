
#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define oops(msg,code) {perror(msg);exit(code);}

enum {
    CUCKOO_OK = 0,
    CUCKOO_SYSTEM_ERROR,
    CUCKOO_RESOURCE_ERROR,
    CUCKOO_PTRACE_ERROR,
    CUCKOO_DEFAULT_ERROR
};

#define ALIGN_LEN 8

void usage(char *prog_name);

#include <sys/reg.h>
#include <sys/user.h>
typedef struct user_regs_struct regs_type;

#include <sys/types.h>
int getNameByPid(char *name, size_t name_len, pid_t pid);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_H__*/
