# include "./debugger.hpp"

int debugging(ELFinfo* infoHandle,char** tracArgs, char** envp){
    pid_t traceePid;
    long trap,orig;
    int status;
    if((traceePid = fork()) < 0 ){
        perror("fork error");
        exit(-1);
    }
    if(traceePid == 0){
        printf("child: execve program %d\n",traceePid);
        if(ptrace(PTRACE_TRACEME,traceePid,NULL,NULL)<0){
            perror("PTRACE_TRACEME\n");
            exit(-1);
        }

        printf("%s\n",infoHandle->filePath);
        execve(infoHandle->filePath,tracArgs,NULL);
        printf("child: finish execve\n");
        exit(0);
    }
    wait(&status);

    printf("start analysis of pid: %d, breakpoint: %p\n",traceePid,infoHandle->symaddr);
    if((orig = ptrace(PTRACE_PEEKTEXT,traceePid,infoHandle->symaddr,NULL))<0){
        perror("PTRACE_PEEKTEXT");
        exit(-1);
    }
    //printf("%ld\n",orig);
    trap = (orig & ~0xff) | 0xcc;
    //printf("%ld\n",trap);
    
    if (ptrace(PTRACE_POKETEXT, traceePid,infoHandle->symaddr, trap) < 0) {
        perror("PTRACE_POKETEXT");
        exit(-1); 
    }
    
    trace:
    if (ptrace(PTRACE_CONT, traceePid, NULL, NULL) < 0) { 
        perror("PTRACE_CONT");
        exit(-1);
    }
    wait(&status);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if (ptrace(PTRACE_GETREGS, traceePid, NULL, &infoHandle->regs) < 0) { 
            perror("PTRACE_GETREGS");
            exit(-1);
        }
        printf("%%rcx: %llx\n%%rdx: %llx\n%%rbx: %llx\n"
            "%%rax: %llx\n%%rdi: %llx\n%%rsi: %llx\n"
            "%%r8: %llx\n%%r9: %llx\n%%r10: %llx\n"
            "%%r11: %llx\n%%r12 %llx\n%%r13 %llx\n"
            "%%r14: %llx\n%%r15: %llx\n%%rsp: %llx",
            infoHandle->regs.rcx, infoHandle->regs.rdx, infoHandle->regs.rbx,
            infoHandle->regs.rax, infoHandle->regs.rdi, infoHandle->regs.rsi,
            infoHandle->regs.r8, infoHandle->regs.r9, infoHandle->regs.r10,
            infoHandle->regs.r11, infoHandle->regs.r12, infoHandle->regs.r13,
            infoHandle->regs.r14, infoHandle->regs.r15, infoHandle->regs.rsp);
        printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n",
        infoHandle->filePath,traceePid, infoHandle->symaddr);
        printf("\nPlease hit any key to continue: ");
        getchar();
        if (ptrace(PTRACE_POKETEXT, traceePid, infoHandle->symaddr, orig) < 0) {
            perror("PTRACE_POKETEXT"); exit(-1); }
        
        infoHandle->regs.rip = infoHandle->regs.rip - 1;
        
        if (ptrace(PTRACE_SETREGS, traceePid, NULL, &infoHandle->regs) < 0) {
            perror("PTRACE_SETREGS");exit(-1); }
        
        if (ptrace(PTRACE_SINGLESTEP, traceePid, NULL, NULL) < 0) { 
            perror("PTRACE_SINGLESTEP");
            exit(-1);
        }
        wait(NULL);
        if (ptrace(PTRACE_POKETEXT, traceePid, infoHandle->symaddr, trap) < 0) {
            perror("PTRACE_POKETEXT");
        exit(-1); }
        goto trace;

    }
    //sleep(20);
    printf("debugging finish\n");
    return 1;


}

Elf64_Addr searchSymbol(ELFinfo* infoHandle, const char* symname){
    char* strtab = NULL;
    Elf64_Sym *symtab = NULL;
    uint16_t secSize = 0;
    // the sh_link of section .symtab and .dynsym is the index of the associated string table 
    for (int i = 0 ;i<infoHandle->ehdr->e_shnum; i++){
        if (infoHandle->shdr[i].sh_type == SHT_SYMTAB){
            strtab = (char*)&infoHandle->mem[infoHandle->shdr[infoHandle->shdr[i].sh_link].sh_offset];
            symtab = (Elf64_Sym*)&infoHandle->mem[infoHandle->shdr[i].sh_offset];
            secSize = infoHandle->shdr[i].sh_size;
            for (int j = 0;j<(secSize/sizeof(Elf64_Sym));j++){                
                //printf("%p\n",symtab->st_value);
                if(!strcmp(&strtab[symtab->st_name],symname)){
                    printf("found symbol: %s",symname);
                    return (symtab->st_value);
                }
                symtab++;
            }
        }
    }

}
int searchSection(ELFinfo* infoHandle,const char* secname){
    
    uint16_t symindex  = infoHandle->ehdr->e_shstrndx;
    uint16_t nowSymOffset;
    Elf64_Shdr* now = infoHandle->shdr;

    for(int i = 0;i<infoHandle->ehdr->e_shnum;i++){
        nowSymOffset = infoHandle->shdr[symindex].sh_offset+infoHandle->shdr[i].sh_name;
        
        if (!strcmp((char*)&infoHandle->mem[nowSymOffset],secname)){
            printf("found");
            return i;
        }
    }
    return -1;
}

int main(int argc, char** argv, char** envp){

    int fd;
    char* tracArgs[2];
    ELFinfo infoHandle;
    struct stat* progst;
    if (argc != 3){
        printf("Usage: %s <program> <function>\n",argv[0]);
        exit(0);
    }
    if ((infoHandle.filePath = strdup(argv[1])) == NULL ){
        perror("strdup error\n");
        exit(-1);
    }
    tracArgs[0] = infoHandle.filePath;
    tracArgs[1] = NULL;

    if ((infoHandle.symname = strdup(argv[2])) == NULL){
        perror("strdup error\n");
        exit(-1);
    }
    if ((fd = open(infoHandle.filePath,O_RDONLY))<0){
        perror("open error\n");
        exit(-1);
    }
    if (fstat(fd,progst) < 0){
        perror("fstat error\n");
        exit(-1);
    }
    infoHandle.mem = (uint8_t *)mmap(NULL,progst->st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if (infoHandle.mem == MAP_FAILED){
        perror("mmap error\n");
        exit(-1);
    }

    infoHandle.ehdr = (Elf64_Ehdr *)infoHandle.mem;
    infoHandle.phdr = (Elf64_Phdr *)(infoHandle.mem+infoHandle.ehdr->e_phoff);
    infoHandle.shdr = (Elf64_Shdr *)(infoHandle.mem+infoHandle.ehdr->e_shoff);

    if (memcmp(infoHandle.ehdr->e_ident,"\x7f\x45\x4c\x46",4) || infoHandle.ehdr->e_type != ET_EXEC){
        perror("not a elf");
        exit(-1);
    }

    if (infoHandle.ehdr->e_shstrndx == 0 || infoHandle.ehdr->e_shoff == 0 || infoHandle.ehdr->e_shnum == 0){
        printf("no section header table found\n");
        exit(-1);
    }
    // if ((infoHandle.symaddr = searchSection(&infoHandle,".text")) == NULL){
    //     printf("123");
    //     exit(-1);
    // }

    /*get symbol address*/
    if ((infoHandle.symaddr = searchSymbol(&infoHandle,infoHandle.symname)) == NULL){
        printf("symbol %s not found",infoHandle.symname);
        exit(-1);
    }
    printf("~~%p~~\n",(void*)infoHandle.symaddr);
    // char* aaa[2] = {"/bin/ls",NULL};
    // execve("/bin/ls",aaa,envp);
    if(!debugging(&infoHandle,tracArgs,envp)){
        perror("debug error");
        exit(-1);
    }
    close(fd);


    printf("finish\n");
}