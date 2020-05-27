
#ifndef __CUCKOO_H__
#define __CUCKOO_H__

#ifdef __cplusplus
extern "C" {
#endif 

    //  others:
    //      1. using process_vm_readv()/process_vm_writev() replace PTRACE_PEEKTEXT/PTRACE_POKETEXT
    //      2. using mmap() to implement VirtualAllocEx() in linux
    //
    //
    //   TODO: Death under ptrace  link: http://man7.org/linux/man-pages/man2/ptrace.2.html

    #include <stdlib.h>
    typedef struct cuckoo_context_s {
        pid_t target_pid;
        int word_size;
        int inject_type;
        char *injected_filename;
    }cuckoo_context;
    
#ifdef __cplusplus
}
#endif

#endif /* __CUCKOO_H__ */
