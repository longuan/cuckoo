
#include <stdio.h>
#include <unistd.h>

int func()
{
    static int count = 1;
    while(1)
    {
        sleep(count++);
        printf("Hello World!!");
        printf(" -- for %d times\n", count-1);
    }
    return 0;
}

int main(void)
{
    return func();
}
