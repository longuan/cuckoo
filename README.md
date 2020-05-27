## cuckoo

The cuckoo never builds a nest, but lays its eggs in the nests of other birds.

## 使用

### 编译

cuckoo可以编译为两种架构：

1. x86架构，用来将32位的代码注入到32位的进程。
2. x64架构，用来将64位的代码注入到64位的进程。

编译x86架构的cuckoo：`cmake . -DARCH=x86 && make`

编译x64架构的cuckoo：`cmake . -DARCH=x64 && make`



### 运行

cuckoo有三种工作方式，分别用于注入shellcode（一段用于获取权限的汇编代码），library（链接库文件），elf（完整的Linux下的可执行文件）到目标进程。

#### shellcode

1. 先编译出来example_process
2. 运行example_process
3. 找出example_process的pid，运行cuckoo
   - `sudo ./build/bin/cuckoo -m shellcode -i ./example/example_shellcode64 -p 79283`


#### library

1. 先编译出来example_process和libexample.so
2. 运行example_process
3. 找出example_process的pid，运行cuckoo
   - `sudo ./build/bin/cuckoo -m lib -i libexample.so -p 79283`

#### elf（目前只支持x86）

1. 先编译出来example_process和example_elf
2. 运行example_process
3. 找出example_process的pid，运行cuckoo
   - `sudo ./build/bin/cuckoo -m elf -i example_elf -p 2901`


## 原理

读写一个不相关进程的进程空间，Windows中有OpenProcess()、VirtualAllocEx()、WriteProcessMemory()和CreateRemoteThread()等一系列API。而Linux平台下，则只有一个ptrace系统调用可用。


ptrace系统调用有很多的request类型，用的比较多的有：

- PTRACE_TRACEME，用于父进程跟踪子进程的执行
- PTRACE_ATTACH PTRACE_DETACH，附加/分离一个目标进程，这个目标进程一般不是子进程
- PTRACE_PEEKTEXT PTRACE_PEEKDATA，从指定位置读取一个字的内容
- PTRACE_POKETEXT PTRACE_POKEDATA，向指定位置写入一个字的内容
- PTRACE_GETREGS PTRACE_SETREGS，读取/设置目标进程此时的寄存器
- PTRACE_GETSIGINFO PTRACE_SETSIGINFO，读取/设置目标进程的信号信息
- PTRACE_CONT 指示目标进程继续运行


通过ptrace，可以实现很强大的功能，比如最基本的——读写目标进程的进程空间。但是，要实现注入任意代码到目标进程，并且在目标进程中执行，就要处理更多事情。


### 注入shellcode

shellcode是一段用于利用软件漏洞而执行的代码。一般来说，shellcode用来劫持控制流，进而执行攻击者的任意命令。example文件夹下的example_shellcode32和example_shellcode64两个文件，分别是32位和64位平台下的执行`system("/bin/sh")`的二进制数据。当然，注入shellcode之后所能做的事取决于shellcode的内容。


shellcode的注入分为两步：1. 把shellcode注入到进程空间；2. 执行shellcode。具体来说，先在目标进程中找具有执行权限的区域，可以通过/proc目录下的maps文件看到。然后将shellcode内容写入到此可执行区域。最后设置eip/rip为shellcode的起始地址，恢复目标进程的执行。


### 注入library

前面shellcode注入会把shellcode内容写入到目标进程的进程空间，这里library注入则不需要把library文件的内容写入到目标进程的进程空间。而是借助llibc中的`__libc_dlopen_mode()`。`__libc_dlopen_mode`的参数是动态链接库的路径，之后会自动加载动态链接库到进程空间。所以只需要提供给目标进程一个文件路径，在目标进程中执行`__libc_dlopen_mode`就可以了，把更多的事情交给操作系统来解决。


example文件夹下的libexample.c文件是一个示例文件，用`__attribute__((constructor))`关键字修饰的函数会在动态链接库被加载之后自动被调用。注入library成功之后会看到"Hello World from libexample!!"消息。


library注入的核心是一段汇编代码，这段汇编是要被写入目标进程空间中并执行的。这段汇编代码先后调用了malloc、`__libc_dlopen_mode`、free三个系统调用。malloc用于申请空间，存储动态链接库文件的路径名，之后作为参数调用`__libc_dlopen_mode`，最后把这个堆块给释放掉。三个系统调用的执行是在目标进程中发生的，对于每个系统调用的结果获取，使用的是"int 3"插桩，也就是预先插入调试断点。


这部分的东西参考了https://github.com/gaffe23/linux-inject的很多内容。


### 注入ELF


进程的执行需要从磁盘上读入一个可执行文件，往往这个进程从生到死都与这个可执行文件绑定，除非调用了exec族函数。同样地，要达到注入ELF的目的，可以像library注入一样，借助exec这个函数，让操作系统替我们完成绝大多数事情。但是这样的话，就不是“inject”那个意思了，更像是“replace”，所以选择另一种方式——解析elf文件、写入二进制代码和执行代码。


一个磁盘上的elf文件，如何被加载到内存中运行？一般来说，这不是我们需要关心的事情。但是现在需要把磁盘上的一个elf文件注入到另一个进程中执行，我们就需要手动模拟这个过程。简单来说，这个过程分为三部分：

1. elf文件展开，从文件视图展开为内存映像视图。
2. 偏移重定位，在被注入到另一个进程的某个位置之后，对于绝对地址的引用将失效
3. 符号解析，目前是对plt和got段的指针修正，需适配更多例子


在elf解析完成之后，相当于把elf文件变成了一个大型的“shellcode”。之后将此写入到目标进程中并执行。


example文件夹下example_elf.c文件是一个示例，编译后注入到目标进程可以看到“Hello World from example_elf!”消息。后面的“int 3”是为了得知被注入的elf何时执行结束，结束之后会恢复目标进程原来的执行环境。