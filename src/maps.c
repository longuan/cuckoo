
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "maps.h"

#define MAXLEN 128

maps_item* mapsParse(pid_t target_pid)
{

    char filename[24];
    snprintf(filename, 24, "/proc/%d/maps", target_pid);
    FILE *maps_file = fopen(filename, "r");
    if(maps_file == NULL) oops("open maps file error ", CUCKOO_RESOURCE_ERROR);
    
    maps_item *head, *tmp, *tmp_prev;
    head = tmp = tmp_prev = (maps_item *)malloc(sizeof(maps_item));
    if(tmp == NULL) oops("malloc error ", CUCKOO_RESOURCE_ERROR);
    char line[128];
    if((fgets(line, 128, maps_file)) == NULL) oops("fgets error ", CUCKOO_DEFAULT_ERROR);

    do{
        tmp->elf_name = (char *)malloc(MAXLEN);
        memset(tmp->elf_name, 0, MAXLEN);
        sscanf(line, "%lx-%lx %4s %*s %*s %*s %127s", &tmp->start_addr,
                &tmp->end_addr, &tmp->permission, tmp->elf_name);
        tmp_prev->next = tmp;
        tmp->next = NULL;
        tmp_prev = tmp;
    } while((fgets(line, 128, maps_file))!= NULL &&\
            (tmp=(maps_item *)malloc(sizeof(maps_item)))!=NULL);

    fclose(maps_file);
    return head;
}


void destoryList(maps_item *list)
{
    maps_item *tmp;
    while(list)
    {
        if(list->elf_name) free(list->elf_name);
        tmp = list->next;
        free(list);
        list = tmp;
    }
}

void printItem(maps_item *list)
{
    while(list)
    {
        printf("%lx-%lx %s %s\n", list->start_addr, list->end_addr,\
                                  list->permission, list->elf_name);
        list = list->next;
    }
}

maps_item *getAttrAddr(maps_item *list, char c)
{
    while(list)
    {
        if(strchr(list->permission, c) != NULL) return list;
        list = list->next;
    }
    return NULL;
}

maps_item *getExecutableAddr(maps_item *list)
{
    return getAttrAddr(list, 'x');
}

maps_item *getELFNameContain(maps_item *list, char *str)
{
    while(list)
    {
        if(strstr(list->elf_name, str)) return list;
        list = list->next;
    }
    return NULL;
}
