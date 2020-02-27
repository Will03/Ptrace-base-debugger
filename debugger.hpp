#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>
#include<elf.h>

#include <sys/types.h> 
#include <sys/user.h> 
#include <sys/stat.h> 
#include <sys/ptrace.h> 
#include <sys/mman.h>
#include <sys/wait.h>

typedef struct {
    char* filePath;
    char* symname;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;
    uint8_t *mem;

    Elf64_Addr symaddr;
    struct user_regs_struct regs;
    // struct user_regs_struct pt_reg;

} ELFinfo;