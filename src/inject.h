
#ifndef __INJECT_H__
#define __INJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

    int ptraceAttach(pid_t pid);
    int ptraceDetach(pid_t pid);
    int ptraceGetRegs(pid_t pid, regs_type *regs);
    int ptraceSetRegs(pid_t pid, regs_type *regs);
    int ptraceGetMems(pid_t pid, long address, unsigned char *data, size_t data_len);
    int ptraceSetMems();
    int ptraceCont(pid_t pid);

#ifdef __cplusplus
}
#endif

#endif

