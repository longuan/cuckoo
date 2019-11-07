# cuckoo
The cuckoo never builds a nest, but lays its eggs in the nests of other birds.


TODO:
1. 统一数据类型，屏蔽平台架构之间的差异。比如尽量不要用long类型，而使用固定大小的数据类型。intptr_t始终与地址位数相同，所以比较适合指针。
2. 用更好的方法代替ptrace_cont中的nanosleep
3. 用getopt 实现main函数