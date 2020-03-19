# cuckoo
The cuckoo never builds a nest, but lays its eggs in the nests of other birds.

## 复现

### 编译cuckoo

cuckoo可以编译为两种架构：
1. x86架构，用来将32位的代码注入到32位的进程。
2. x64架构，用来将64位的代码注入到64位的进程。

编译x86架构的cuckoo：`cmake . -DARCH=x86 && make`

编译x64架构的cuckoo：`cmake . -DARCH=x64 && make`

### shellcode

1. 先在example文件夹下编译出来example_process
2. 运行example_process
3. 找出example_process的pid，运行cuckoo
    - `sudo ./build/bin/cuckoo -m shellcode -w 64 -i ./example/example_shellcode64 -p 79283`


### library

1. 先在example文件夹下编译出来example_process和libexample.so
2. 运行example_process
3. 找出example_process的pid，运行cuckoo
    - `sudo ./build/bin/cuckoo -m lib -w 64 -i libexample.so -p 79283`


## TODO 

- 由于x86和x64的`struct user_regs_struct`的不同，需要在cmake时指定架构。能否将这点调整到运行时。
- 新增函数function2shellcode
- 注入ELF文件