// #define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "elfinject.h"
#include "inject.h"
#include "cuckoo.h"
#include "utils.h"

// https://github.com/shinh/tel_ldr/blob/master/elf-clean.c

void undefined()
{
    fprintf(stderr, "undefined function is called\n");
    abort();
}

// 需要修复PLT表中跳转到GOT表的jmp指令的目的地址
static void repair_PLT(void *addr, size_t addr_len, long base_diff)
{
    return 0;
}

static void relocate(const char *reloc_type,
              Elf32_Rel *rel, int relsz,
              Elf32_Sym *dsym, char *dstr, pid_t target_pid, long base_diff, long base_diff_2)
{
    int i;
    for (i = 0; i < relsz / sizeof(*rel); rel++, i++)
    {
        int *addr = (int *)rel->r_offset;
        // the address of puts.got in the memory has changed 
        // char * is necessary
        addr = (char*)addr + base_diff_2;
        rel->r_offset = (char*)rel->r_offset + base_diff;
        int type = ELF32_R_TYPE(rel->r_info);
        Elf32_Sym *sym = dsym + ELF32_R_SYM(rel->r_info);
        char *sname = dstr + sym->st_name;
        void *val = getTargetLibcallAddr(target_pid, sname);

        printf("%s: %p %s(%d) %d => %p\n",
               reloc_type, (void *)addr, sname, sym, type, val);

        switch (type)
        {
        case R_386_32:
        {
            *addr += (int)val;
        }
        case R_386_COPY:
        {
            if (val) {
                *addr = *(int *)val;
            }
            else {
                fprintf(stderr, "undefined: %s\n", sname);
                abort();
            }
        }
        case R_386_GLOB_DAT:
        {
            break;
        }
        case R_386_JMP_SLOT:
        {
            if (val) {
                *addr = (int)val;
            }
            else {
                *addr = (int)&undefined;
            }
            break;
        }
        }
    }
}

int injectELF(cuckoo_context *context)
{
    // 分四步：
    // 1. cuckoo进程malloc一段内存用来存储ELF展开后的内容。称此地址为malloc_addr。
    //    称被注入进程的内存起始页为target_base_addr。ELF的基址为base_addr。
    // 2. 把ELF分段展开到malloc_addr
    // 3. 对展开后的malloc_addr内容进行重定位，同时解析got表内的值。把重定位表里的内容填换为以target_base_addr为基址，
    //    但要注意ELF的基址不再为base_addr，而是malloc_addr
    // 4. 把展开和修正后的ELF注入到目标进程内存
    int i, fd;
    int entry, phoff, phnum;
    Elf32_Ehdr ehdr;
    void *mapped_addr = NULL;
    size_t mapped_size = 0;
    void *target_addr = getMapsItemAddr(context->target_pid, "r-x");
    void *base_addr = 0;
    long base_diff = 0;   //  target_base_addr - base_addr
    long base_diff_2 = 0; //  malloc_addr - base_addr

    printf("loading %s\n", context->injected_filename);
    fd = open(context->injected_filename, O_RDONLY);
    if (fd < 0)
        oops("open injected file failed ", CUCKOO_SYSTEM_ERROR);
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
        oops("reading ELF header failed ", CUCKOO_SYSTEM_ERROR);

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
        oops("not elf ", CUCKOO_DEFAULT_ERROR);
    if (ehdr.e_type != ET_EXEC || ehdr.e_machine != EM_386)
        oops("not i386 exec ", CUCKOO_DEFAULT_ERROR);

    entry = ehdr.e_entry;
    phoff = ehdr.e_phoff;
    phnum = ehdr.e_phnum;
    printf("old_entry=%x phoff=%x phnum=%x\n", entry, phoff, phnum);  

    for (i = 0; i < phnum; i++)
    {
        int poff, paddr, pfsize, psize, pafsize, pflag;
        Elf32_Phdr phdr;
        lseek(fd, phoff+sizeof(phdr)*i, SEEK_SET);
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
            oops("reading program header failed ", CUCKOO_SYSTEM_ERROR);
        poff = phdr.p_offset;
        paddr = phdr.p_vaddr;
        pfsize = phdr.p_filesz;
        psize = phdr.p_memsz;
        pflag = phdr.p_flags;
        printf("%d %d %p %x\n", phdr.p_type, poff, paddr, pfsize);
        switch (phdr.p_type)
        {
        case PT_LOAD:
        {
            int prot = 0;
            if (pflag & 1){
                prot |= PROT_EXEC;
                base_addr = paddr;
                base_diff = target_addr - base_addr;
                entry = (void*)entry + base_diff;
            }
            if (pflag & 2)
                prot |= PROT_WRITE;
            if (pflag & 4)
                prot |= PROT_READ;
            psize += paddr & 0xfff;
            pfsize += paddr & 0xfff;
            poff -= paddr & 0xfff;
            paddr &= ~0xfff;
            pafsize = (pfsize + 0xfff) & ~0xfff;
            psize = (psize + 0xfff) & ~0xfff;
            printf("PT_LOAD size=%d fsize=%d flag=%d addr=%x prot=%d poff=%d\n",
                   psize, pafsize, pflag, paddr, prot, poff);
            // if (mmap((void *)paddr, pafsize, prot, MAP_FILE | MAP_PRIVATE | MAP_FIXED,
            //          fd, poff) == MAP_FAILED)
            int temp_size = mapped_size;
            mapped_size += pafsize;
            if((mapped_addr = realloc(mapped_addr, mapped_size)) == NULL)
            {
                oops("realloc(file) ", CUCKOO_SYSTEM_ERROR);
            }
            // memcpy(mapped_addr, fd+poff, pfsize);
            lseek(fd, poff, SEEK_SET);
            read(fd, mapped_addr+temp_size, pfsize);
            
            if ((prot & PROT_WRITE))
            {
                for (; pfsize < pafsize; pfsize++)
                {
                    int *p = mapped_addr;
                    p[pfsize] = 0;
                }
            }
            //     if (pfsize != psize)
            //     {
            //         if (mmap((void *)(paddr + pfsize),
            //                  psize - pfsize, prot, MAP_ANON | MAP_PRIVATE,
            //                  -1, 0) == MAP_FAILED)
            //         {
            //             error("mmap(anon)");
            //         }
            //     }
            // }
            break;
        }
        case PT_DYNAMIC:
        {
            char *dstr = NULL, *dstr_injector;
            Elf32_Sym *dsym = NULL, *dsym_injector;
            Elf32_Rel *rel = NULL, *rel_injector;
            int relsz = 0, pltrelsz = 0;
            base_diff_2 = mapped_addr - base_addr;
            Elf32_Dyn *dyn;
            puts("PT_DYNAMIC");
            for (dyn = (Elf32_Dyn *)((void*)paddr+ base_diff_2); dyn->d_tag != DT_NULL; dyn++)
            {
                Elf32_Addr dval = dyn->d_un.d_ptr;
                switch (dyn->d_tag)
                {
                case DT_PLTRELSZ:
                {
                    pltrelsz = dyn->d_un.d_val;
                    printf("pltrelsz: %d\n", pltrelsz);
                    break;
                }
                case DT_STRTAB:
                {
                    dstr = (char *)dyn->d_un.d_ptr;
                    dyn->d_un.d_ptr = (void*)dstr + base_diff;
                    dstr = (void *)dstr + base_diff_2;

                    // printf("dstr: %p %s\n", dyn->d_un.d_ptr, (dyn->d_un.d_ptr) + 1);
                    break;
                }
                case DT_SYMTAB:
                {
                    dsym = (Elf32_Sym *)dyn->d_un.d_ptr;
                    dyn->d_un.d_ptr = (void*)dsym + base_diff;
                    dsym = (Elf32_Sym *)((void*)dsym + base_diff_2);

                    printf("dsym: %p\n", dyn->d_un.d_ptr);
                    break;
                }
                case DT_REL:
                {
                    rel = (Elf32_Rel *)dyn->d_un.d_ptr;
                    dyn->d_un.d_ptr = (void *)rel + base_diff;
                    rel = (Elf32_Rel *)((void*)rel + base_diff_2);
                    printf("rel: %p\n", dyn->d_un.d_ptr);
                    break;
                }
                case DT_RELSZ:
                {
                    relsz = dyn->d_un.d_val;
                    printf("relsz: %d\n", relsz);
                    break;
                }
                case DT_RELENT:
                {
                    int relent = dyn->d_un.d_val;
                    printf("relent: %d\n", relent);
                    if (relent != sizeof(*rel))
                        oops("unexpected RELENT ", CUCKOO_DEFAULT_ERROR);
                    break;
                }
                case DT_PLTREL:
                {
                    int pltrel = dyn->d_un.d_val;
                    printf("pltrel: %d\n", pltrel);
                    if (pltrel != DT_REL)
                        oops("unexpected PLTREL ", CUCKOO_DEFAULT_ERROR);
                    break;
                }
                default:
                    if (((void*)(dyn->d_un.d_val) - base_addr) > 0){
                        dyn->d_un.d_ptr = (char *)rel + base_diff;
                    }
                    printf("unknown DYN %d %x\n", dyn->d_tag, dyn->d_un.d_val);
                }
            }
            if (!dsym || !dstr)
                oops("no dsym or dstr ", CUCKOO_DEFAULT_ERROR);


            relocate("rel", rel, relsz, dsym, dstr, context->target_pid, base_diff,base_diff_2);
            relocate("pltrel", rel + relsz / sizeof(*rel), pltrelsz, dsym, dstr, context->target_pid, base_diff,base_diff_2);
        }
        default:
            printf("unknown PT %d\n", phdr.p_type);
        }
    }

    // get content of string table
    Elf32_Shdr st_shdr;
    printf("shstrndx is %x\n", ehdr.e_shstrndx);
    lseek(fd, (off_t)(ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shstrndx), SEEK_SET);
    read(fd, &st_shdr, ehdr.e_shentsize);
    lseek(fd, (off_t)st_shdr.sh_offset, SEEK_SET);
    char *st_names = malloc(st_shdr.sh_size);
    read(fd, st_names, st_shdr.sh_size);

    // relocate PLT entry 
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        Elf32_Shdr shdr;
        lseek(fd, (off_t)(ehdr.e_shoff + ehdr.e_shentsize * i), SEEK_SET);
        read(fd, &shdr, ehdr.e_shentsize);

        char *section_name = st_names + shdr.sh_name;
        if (!strcmp(section_name, ".plt"))
        {
            unsigned char *malloced_plt_addr = mapped_addr + shdr.sh_offset;
            // 16 for x86
            for (size_t i = 0; i < shdr.sh_size; i+=16)
            {
                unsigned long *got_addr = malloced_plt_addr + i+2;
                *got_addr = *got_addr + base_diff;
            }
        }
    }

    {
        pid_t target_pid = context->target_pid;
        ptraceAttach(target_pid);

        struct user_regs_struct old_regs;
        ptraceGetRegs(target_pid, &old_regs);
        struct user_regs_struct new_regs;
        memcpy(&new_regs, &old_regs, sizeof(old_regs));

        // assume ELF only use 3 page. 1(text) for r-e, 2(data) for r-w
        unsigned char *backup = malloc(mapped_size);
        ptraceGetMems(target_pid, target_addr, backup, 0x3000);
        ptraceSetMems(target_pid, target_addr, mapped_addr, 0x1000);
        ptraceSetMems(target_pid, target_addr+0x1000, mapped_addr+0x1000, 0x2000);
        // old_regs.eip = entry;
        // 0x8048426 is the main function address in the ./example/example_elf
        new_regs.eip = 0x8048426 + base_diff;

        ptraceSetRegs(target_pid, &new_regs);
        ptraceCont(target_pid);

        restoreStateAndDetach(target_pid, target_addr, backup, 0x3000, &old_regs);
        free(st_names);
        free(backup);
        free(mapped_addr);
    }

    printf("start!: %s %x\n", context->injected_filename, entry);
    return CUCKOO_OK;
}