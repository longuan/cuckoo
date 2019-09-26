
#ifndef __SHELLCODE_H__
#define  __SHELLCODE_H__

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>
int injectShellcode(pid_t pid, unsigned char *shellcode, size_t shellcode_len);


#ifdef __cplusplus
}
#endif

#endif
