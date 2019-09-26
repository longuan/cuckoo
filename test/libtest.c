#include <stdio.h>

void printHello()
{
    printf("Hello World from libtest!!\n");
}


__attribute__((constructor))
void loadMsg()
{
    printHello();
}
