
#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct process_memory_item{
        long start_addr;
        long end_addr;
        char permission[4];
        int reserve;
        struct process_memory_item *next;
    } process_memory_item;

    // read /proc/<pid>/maps to get process memory layout
    process_memory_item* mapsParse(pid_t pid);
    void destory(process_memory_item *list);

    void print_item(process_memory_item *list);

#ifdef __cplusplus
}
#endif

#endif /*__UTILS_H__*/
