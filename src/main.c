//
// Created by longuan on 2019/11/5.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"
#include "cuckoo.h"
#include "library.h"
#include "shellcode.h"

static void usage(char *argv0)
{
    printf("%s inject shellcode or library into another process\n\n"
            
            "Required parameters:\n"
            "  -m mod        - injection mode (shellcode or lib)\n"
            "  -w word       - word size (32 or 64)\n"
            "  -i input      - shellcode or library file path\n"
            "  -p pid        - target pid\n\n"
            
            "Optional parameters:\n"
            "  -q quiet      - quiet mode\n",

            argv0);
    exit(1);
}

int main(int argc, char *argv[])
{
    pid_t target_pid = 0;
    int quiet = 0, word_size = 0;
    char *mode = 0, *input = 0;
    char cmdline_filename[32];

    int opt;
    while ((opt = getopt(argc, argv, "m:w:i:p:q")) > 0)
    {
        switch (opt) {
            case 'm':
                if(mode) oops("Multiple -m options", 1);
                mode = optarg;
                break;
            case 'w':
                if(word_size) oops("Multiple -w options", 1);
                word_size = atoi(optarg);
                if(!(word_size==32||word_size==64)) {
                    printf("word size is 32 or 64\n");
                    exit(1);
                }
                break;
            case 'i':
                if(input) oops("Multiple -i options", 1);
                input = realpath(optarg, NULL);
                if(access(input, F_OK|R_OK)!=0){
                    printf("input file not found\n");
                    exit(1);
                }
                break;
            case 'p':
                if(target_pid) oops("Multiple -p options", 1);
                target_pid = atoi(optarg);
                snprintf(cmdline_filename, 32, "/proc/%d/cmdline", target_pid);
                if(access(cmdline_filename, F_OK|R_OK)!=0){
                    printf("target process not found\n");
                    exit(1);
                }
                break;
            case 'q':
                quiet = 1;
                break;
            default : usage(argv[0]);
        }
    }

    if(optind != argc || optind == 1 || !mode) usage(argv[0]);
    
    cuckoo_context context;
    context.target_pid = target_pid;
    context.mem_maps = mapsParse(target_pid);
    context.word_size = word_size;
    context.injected_filename = input;
    context.inject_type = -1;

    if(!strcmp(mode, "shellcode")){
        context.inject_type = 0;
        int result = injectShellcode(&context);
        if(result != CUCKOO_OK)
            oops("error", CUCKOO_DEFAULT_ERROR);
    }
    if((!strcmp(mode, "lib")) || (!strcmp(mode, "library"))){
        context.inject_type = 1;
        int result = injectLibrary(&context);
        if (result != CUCKOO_OK)
            oops("error", CUCKOO_DEFAULT_ERROR);
    }
    // char process_name[32];
    // getNameByPid(process_name, 32, target_pid);
    // printf("[*] injecting %s into %s\n", lib_path, process_name);
    return 0;
}

