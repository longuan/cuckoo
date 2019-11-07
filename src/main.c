//
// Created by longuan on 2019/11/5.
//
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "cuckoo.h"
#include "library.h"


int injectlib_main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("Usage:\n\t%s <pid> <lib_path>\n", argv[0]);
        return 0;
    }


    pid_t target_pid = atoi(argv[1]);
    cuckoo_context context;
    if(init_context(&context, target_pid) != CUCKOO_OK)
    {
        printf("no such process!\n");
        return 1;
    }

    char* lib_name = argv[2];
    char* lib_path = realpath(lib_name, NULL);
    if(!lib_path)
    oops("lib_path is wrong! ", CUCKOO_RESOURCE_ERROR);

    context.injected_filename = lib_path;
    char process_name[32];
    getNameByPid(process_name, 32, target_pid);
    printf("[*] injecting %s into %s\n", lib_path, process_name);

    if (injectLibrary(&context) != CUCKOO_OK)
    {
        oops("error ", CUCKOO_DEFAULT_ERROR);
    }
    clean_context(&context);
    return 0;
}

