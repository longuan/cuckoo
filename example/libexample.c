#include <stdio.h>

__attribute__((constructor))
void loadMsg()
{
    printf("Hello World from libexample!!\n");
}
