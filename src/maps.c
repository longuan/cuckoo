
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "maps.h"

process_memory_item* mapsParse(pid_t target_pid)
{
    char filename[24];
    snprintf(filename, 24, "/proc/%d/maps", target_pid);
    FILE *maps_file = fopen(filename, "r");
    if(maps_file == NULL) oops("open maps file error ", CUCKOO_RESOURCE_ERROR);
    
    process_memory_item *head, *tmp, *tmp_prev;
    head = tmp = tmp_prev = malloc(sizeof(process_memory_item));
    if(tmp == NULL) oops("malloc error ", CUCKOO_RESOURCE_ERROR);
    char line[128];
    if((fgets(line, 128, maps_file)) == NULL) oops("fgets error ", CUCKOO_DEFAULT_ERROR);

    do{
        sscanf(line, "%lx-%lx %s %*s %*s", &tmp->start_addr,
                &tmp->end_addr, &tmp->permission);
        tmp_prev->next = tmp;
        tmp->next = NULL;
        tmp_prev = tmp;
    } while((fgets(line, 128, maps_file))!= NULL && (tmp=malloc(sizeof(process_memory_item)))!=NULL);

    fclose(maps_file);
    return head;
}


void destory(process_memory_item *list)
{
    process_memory_item *tmp = list;
    while(tmp)
    {
        free(tmp);
        tmp = tmp->next;
    }
}

void print_item(process_memory_item *list)
{
    process_memory_item *tmp = list;
    while(tmp)
    {
        printf("%lx-%lx %s\n", tmp->start_addr, tmp->end_addr, tmp->permission);
        tmp = tmp->next;
    }
}
