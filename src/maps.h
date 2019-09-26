
#ifndef __MAPS_H__
#define __MAPS_H__

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct maps_item_s{
        struct maps_item_s *next;
        unsigned long start_addr;
        unsigned long end_addr;
        char permission[4];
        char *elf_name;
    } maps_item;

    // read /proc/<pid>/maps to get process memory layout
    maps_item* mapsParse(pid_t pid);
    void destoryList(maps_item *list);

    void printItem(maps_item *list);

    maps_item *getAttrAddr(maps_item *list, char c);
    maps_item *getWritableAddr(maps_item *list);
    maps_item *getExecutableAddr(maps_item *list);
    maps_item *getFilenameContain(maps_item *list, char *str);
#ifdef __cplusplus
}
#endif

#endif /*__MAPS_H__*/
