
#ifndef __INJECT_H__
#define __INJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

    int ptraceAttach(pid_t pid);
    int ptraceGetRegs(pid_t pid, regs_type *regs);
    int ptraceSetRegs();
    int ptraceGetMems(pid_t pid, long address, char *data, size_t data_len);
    int ptraceSetMems();

#ifdef __cplusplus
}
#endif

#endif

