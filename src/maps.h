
#ifndef __MAPS_H__
#define __MAPS_H__

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct maps_item_s{
        unsigned long start_addr;
        unsigned long end_addr;
        char permission[4];
        char *elf_name;
        struct maps_item *next;
    } maps_item;

    // read /proc/<pid>/maps to get process memory layout
    maps_item* mapsParse(pid_t pid);
    void destoryList(maps_item *list);

    void printItem(maps_item *list);

    static maps_item *getAttrAddr(maps_item *list, char c);
    inline maps_item *getWritableAddr(maps_item *list)
    {
        return getAttrAddr(list, 'w');
    }

    inline maps_item *getExecutableAddr(maps_item *list)
    {
        return getAttrAddr(list, 'x');
    }

    maps_item *getFilenameContain(maps_item *list, char *str);
#ifdef __cplusplus
}
#endif

#endif /*__MAPS_H__*/
