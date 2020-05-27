#include <stdio.h>

void main(void)
{
    printf("Hello World from example_elf!\n");
    asm("int $3");
    // gcc example_elf.c -o example_elf -m32 -no-pie
}
