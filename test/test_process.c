
#include <stdio.h>
#include <unistd.h>

int func()
{
    static int count = 1;
    while(1)
    {
        count++;
  //      printf("Hello World! -- %d times\n", count);
//        sleep(2);
        // printf(" -- for %d times\n", count-1);
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
