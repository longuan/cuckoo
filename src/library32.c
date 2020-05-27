
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>
#include <elf.h>

#include "library.h"
#include "cuckoo.h"
#include "utils.h"
#include "inject.h"

static void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr)
{
    // here are the assumptions I'm making about what data will be located
    // where at the time the target executes this code:
    //
    //   ebx = address of malloc() in target process
    //   edi = address of __libc_dlopen_mode() in target process
    //   esi = address of free() in target process
    //   ecx = size of the path to the shared library we want to load
    asm("nop \n"
        "nop \n"
        "nop \n"
        "nop");

    // for some reason it's adding 1 to esi, so subtract 1 from it
    asm("dec %esi");

    // call malloc() from within the target process
    asm(
        // choose the amount of memory to allocate with malloc() based on the size
        // of the path to the shared library passed via ecx
        "push %ecx \n"
        // call malloc
        "call *%ebx \n"
        // copy malloc's return value (i.e. the address of the allocated buffer) into ebx
        "mov %eax, %ebx \n"
        // break back in so that the injector can get the return value
        "int $3");

    // call __libc_dlopen_mode() to load the shared library
    asm(
        // 2nd argument to __libc_dlopen_mode(): flag = RTLD_LAZY
        "push $1 \n"
        // 1st argument to __libc_dlopen_mode(): filename = the buffer we allocated earlier
        "push %ebx \n"
        // call __libc_dlopen_mode()
        "call *%edi \n"
        // break back in so that the injector can check the return value
        "int $3");

    // call free() on the previously malloc'd buffer
    asm(
        // 1st argument to free(): ptr = the buffer we allocated earlier
        "push %ebx \n"
        // call free()
        "call *%esi");

    // we already overwrote the RET instruction at the end of this function
    // with an INT 3, so at this point the injector will regain control of
    // the target's execution.
}

static void injectSharedLibrary_end()
{
}

int injectLibrary(cuckoo_context *context)
{
    pid_t target_pid = context->target_pid;
    char *lib_path = context->injected_filename;
    size_t lib_path_len = strlen(lib_path) + 1;

    unsigned long target_mallocAddr = getTargetLibcallAddr(target_pid, "malloc");
    printf("target malloc address: %lx\n", target_mallocAddr);
    unsigned long target_freeAddr = getTargetLibcallAddr(target_pid, "free");
    unsigned long target_dlopenAddr = getTargetLibcallAddr(target_pid, "__libc_dlopen_mode");

    ptraceAttach(target_pid);

    struct user_regs_struct old_regs, regs;

    memset(&old_regs, 0, sizeof(struct user_regs_struct));
    memset(&regs, 0, sizeof(struct user_regs_struct));

    ptraceGetRegs(target_pid, &old_regs);
    memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));

    // find a good address to copy code to
    unsigned long addr = getMapsItemAddr(target_pid, "r-x") + sizeof(long);

    regs.eip = addr;

    regs.ebx = target_mallocAddr;
    regs.edi = target_freeAddr;
    regs.esi = target_dlopenAddr;
    regs.ecx = lib_path_len;
    ptraceSetRegs(target_pid, &regs);

    // figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate.
    size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;
    printf("[*] the bootstrap shellcode len is: %d\n", injectSharedLibrary_size);

    intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;

    // back up whatever data used to be at the address we want to modify.
    unsigned char *backup = malloc(injectSharedLibrary_size * sizeof(char));
    ptraceGetMems(target_pid, addr, backup, injectSharedLibrary_size);

    // set up a buffer to hold the code we're going to inject into the
    // target process.
    unsigned char *bootstrap_code = malloc(injectSharedLibrary_size * sizeof(char));
    memset(bootstrap_code, 0, injectSharedLibrary_size * sizeof(char));

    // copy the code of injectSharedLibrary() to a buffer.
    memcpy(bootstrap_code, injectSharedLibrary, injectSharedLibrary_size - 1);

    // replace push ebp;move ebp, esp; with nops
    size_t nops_start = indexOfBytes(bootstrap_code, injectSharedLibrary_size, "\x90\x90\x90\x90", 4);
    // printf("the nops start: %d\n", nops_start);
    for(int i=0; i<nops_start; i++)
        bootstrap_code[i] = '\x90';

    // overwrite the RET instruction with an INT 3.
    bootstrap_code[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

    // copy injectSharedLibrary()'s code to the target address inside the
    // target process' address space.
    ptraceSetMems(target_pid, addr, bootstrap_code, injectSharedLibrary_size);
    printMem(bootstrap_code, injectSharedLibrary_size);

    ptraceCont(target_pid);

    // at this point, the target should have run malloc(). check its return
    // value to see if it succeeded, and bail out cleanly if it didn't.
    struct user_regs_struct malloc_regs;
    memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
    ptraceGetRegs(target_pid, &malloc_regs);
    unsigned long long targetBuf = malloc_regs.eax;
    if (targetBuf == 0)
    {
        fprintf(stderr, "malloc() failed to allocate memory\n");
        restoreStateAndDetach(target_pid, addr, backup, injectSharedLibrary_size, &old_regs);
        free(backup);
        free(bootstrap_code);
        return CUCKOO_PTRACE_ERROR;
    }

    ptraceSetMems(target_pid, targetBuf, lib_path, lib_path_len);

    // continue the target's execution again in order to call
    // __libc_dlopen_mode.
    ptraceCont(target_pid);

    // TODO: why "/home/zzeo/cuckoo/example/libexample.so" change to
    //           "\x00\x00\x00\x00e/zzeo/cuckoo/example/libexample.so"
    //           "in the targetBuf"
    char lib_path_from_target[128];
    ptraceGetMems(target_pid, targetBuf, lib_path_from_target, 40);
    lib_path_from_target[40] = 0;
    printf("lib_path_from_target: %s\n", lib_path_from_target);
    
    // check out what the registers look like after calling dlopen.
    struct user_regs_struct dlopen_regs;
    memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
    ptraceGetRegs(target_pid, &dlopen_regs);
    unsigned long long libAddr = dlopen_regs.eax;

    // if rax is 0 here, then __libc_dlopen_mode failed, and we should bail
    // out cleanly.
    if (libAddr == 0)
    {
        fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n", lib_path);
        restoreStateAndDetach(target_pid, addr, backup, injectSharedLibrary_size, &old_regs);
        free(backup);
        free(bootstrap_code);
        return CUCKOO_PTRACE_ERROR;
    }

    ptraceCont(target_pid);

    restoreStateAndDetach(target_pid, addr, backup, injectSharedLibrary_size, &old_regs);
    free(backup);
    free(bootstrap_code);
    //
    return CUCKOO_OK;
}
