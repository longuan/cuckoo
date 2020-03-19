
#ifndef __INJECT_H__
#define __INJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

    int ptraceAttach(pid_t pid);
    int ptraceDetach(pid_t pid);
    int ptraceGetRegs(pid_t pid, regs_type *regs);
    int ptraceSetRegs(pid_t pid, regs_type *regs);
    // PEEKTEXT POKETEXT Copy the word data to the address addr 
    // in 32, a word is 32bit. in 64, a word is 64bit
    int ptraceGetMems(pid_t pid, unsigned long address, unsigned char *data, size_t data_len);
    int ptraceSetMems(pid_t pid, unsigned long address, unsigned char *data, size_t data_len);
    int ptraceCont(pid_t pid);

#ifdef __cplusplus
}
#endif

#endif

