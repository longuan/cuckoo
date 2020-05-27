
#include <stdio.h>
#include <unistd.h>

int func()
{
    static int count = 1;
    while(1)
    {
        count++;
    }
    return 0;
}

void n()
{
    printf("fuck off!\n");
    func();
}

int main(void)
{
    return func();
}
