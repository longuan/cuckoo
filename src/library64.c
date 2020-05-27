
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
    //   rdi = address of malloc() in target process
    //   rsi = address of free() in target process
    //   rdx = address of __libc_dlopen_mode() in target process
    //   rcx = size of the path to the shared library we want to load

    asm(
        "nop \n"
        "nop \n"
        "nop \n"
        "nop"
    );
    
    // save addresses of free() and __libc_dlopen_mode() on the stack for later use
    asm(
    // rsi is going to contain the address of free(). it's going to get wiped
    // out by the call to malloc(), so save it on the stack for later
    "push %rsi \n"
    // same thing for rdx, which will contain the address of _dl_open()
    "push %rdx"
    );

    // call malloc() from within the target process
    asm(
    // save previous value of r9, because we're going to use it to call malloc()
    "push %r9 \n"
    // now move the address of malloc() into r9
    "mov %rdi,%r9 \n"
    // choose the amount of memory to allocate with malloc() based on the size
    // of the path to the shared library passed via rcx
    "mov %rcx,%rdi \n"
    // now call r9; malloc()
    "callq *%r9 \n"
    // after returning from malloc(), pop the previous value of r9 off the stack
    "pop %r9 \n"
    // break in so that we can see what malloc() returned
    "int $3"
    );

    // call __libc_dlopen_mode() to load the shared library
    asm(
    // get the address of __libc_dlopen_mode() off of the stack so we can call it
    "pop %rdx \n"
    // as before, save the previous value of r9 on the stack
    "push %r9 \n"
    // copy the address of __libc_dlopen_mode() into r9
    "mov %rdx,%r9 \n"
    // 1st argument to __libc_dlopen_mode(): filename = the address of the buffer returned by malloc()
    "mov %rax,%rdi \n"
    // 2nd argument to __libc_dlopen_mode(): flag = RTLD_LAZY
    "movabs $1,%rsi \n"
    // call __libc_dlopen_mode()
    "callq *%r9 \n"
    // restore old r9 value
    "pop %r9 \n"
    // break in so that we can see what __libc_dlopen_mode() returned
    "int $3"
    );

    // call free() to free the buffer we allocated earlier.
    //
    // Note: I found that if you put a nonzero value in r9, free() seems to
    // interpret that as an address to be freed, even though it's only
    // supposed to take one argument. As a result, I had to call it using a
    // register that's not used as part of the x64 calling convention. I
    // chose rbx.
    asm(
    // at this point, rax should still contain our malloc()d buffer from earlier.
    // we're going to free it, so move rax into rdi to make it the first argument to free().
    "mov %rax,%rdi \n"
    // pop rsi so that we can get the address to free(), which we pushed onto the stack a while ago.
    "pop %rsi \n"
    // save previous rbx value
    "push %rbx \n"
    // load the address of free() into rbx
    "mov %rsi,%rbx \n"
    // zero out rsi, because free() might think that it contains something that should be freed
    "xor %rsi,%rsi \n"
    // break in so that we can check out the arguments right before making the call
    "int $3 \n"
    // call free()
    "callq *%rbx \n"
    // restore previous rbx value
    "pop %rbx"
    );

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

    // now that we have an address to copy code to, set the target's rip to
    // it. we have to advance by 2 bytes here because rip gets incremented
    // by the size of the current instruction, and the instruction at the
    // start of the function to inject always happens to be 2 bytes long.
    regs.rip = addr + 2;

//    rdi, rsi, rdx, rcx, r8, and r9.
    regs.rdi = target_mallocAddr;
    regs.rsi = target_freeAddr;
    regs.rdx = target_dlopenAddr;
    regs.rcx = lib_path_len;
    ptraceSetRegs(target_pid, &regs);

    // figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate.
    size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;
    printf("[*] the bootstrap shellcode len is: %d\n", injectSharedLibrary_size);

    intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;

    // back up whatever data used to be at the address we want to modify.
    unsigned char* backup = malloc(injectSharedLibrary_size * sizeof(char));
    ptraceGetMems(target_pid, addr, backup, injectSharedLibrary_size);

    // set up a buffer to hold the code we're going to inject into the
    // target process.
    unsigned char* bootstrap_code = malloc(injectSharedLibrary_size * sizeof(char));
    memset(bootstrap_code, 0, injectSharedLibrary_size * sizeof(char));

    // copy the code of injectSharedLibrary() to a buffer.
    memcpy(bootstrap_code, injectSharedLibrary, injectSharedLibrary_size - 1);

    // memset(bootstrap_code, 0x90, 0x10);
    size_t nops_start = indexOfBytes(bootstrap_code, injectSharedLibrary_size, "\x90\x90\x90\x90", 4);
    // printf("the nops start: %d\n", nops_start);
    for (size_t i = 0; i < nops_start; i++)
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
    unsigned long long targetBuf = malloc_regs.rax;
    if(targetBuf == 0)
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

    // check out what the registers look like after calling dlopen.
    struct user_regs_struct dlopen_regs;
    memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
    ptraceGetRegs(target_pid, &dlopen_regs);
    unsigned long long libAddr = dlopen_regs.rax;

    // if rax is 0 here, then __libc_dlopen_mode failed, and we should bail
    // out cleanly.
    if(libAddr == 0)
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
