#include <stdio.h>

__attribute__((constructor))
void loadMsg()
{
    printf("Hello World from libexample!!\n");
}


// gcc -fPIC -shared libexample.c libexample.h -o libexample.so  

