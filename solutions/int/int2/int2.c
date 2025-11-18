#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>

#ifndef PORT
#define PORT 10000
#endif

#define MIN(a, b)  ((a) < (b) ? (a) : (b))

#define FLAGSZ 100
char flag[FLAGSZ];
#define POEMSZ 65000
char poem[POEMSZ];

void sendpoem(unsigned short sz)
{
	int n;
	char dummy;
	while (sz > 0) {
		if ( (n = write(1, poem, sz)) < 0 )
			exit(1);
		sz -= n;
	}
	if (read(0, &dummy, 1) < 0)
		exit(1);
}

void child()
{
	int len;

	printf("Welcome to int2\n");

	printf("How many characters? ");
	if (scanf("%d", &len) != 1) {
		fprintf(stderr, "syntax error\n");
		exit(1);
	}
	len = MIN(len, POEMSZ);
	sendpoem(len);
}

#define IOBUFSZ 4096
char obuf[IOBUFSZ];
char ibuf[IOBUFSZ];
char ebuf[IOBUFSZ];
int main()
{
	int lstn, f;
	int enable;
	struct sockaddr_in lstn_addr;

	f = open("flag.txt", O_RDONLY);
	if (f < 0 || read(f, flag, FLAGSZ) <= 0) {
		perror("flag.txt");
		exit(1);
	}
	close(f);
	f = open("poem", O_RDONLY);
	if (f < 0 || read(f, poem, POEMSZ) <= 0) {
		perror("poem");
		exit(1);
	}
	close(f);

	setvbuf(stdin,  ibuf, _IOLBF, IOBUFSZ);
	setvbuf(stdout, obuf, _IOLBF, IOBUFSZ);
	setvbuf(stderr, ebuf, _IOLBF, IOBUFSZ);
	lstn = socket(AF_INET, SOCK_STREAM, 0);
	if (lstn < 0) {
		perror("socket");
		return 1;
	}
	enable = 1;
	if (setsockopt(lstn, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt");
		return 1;
	}
	bzero(&lstn_addr, sizeof(lstn_addr));

	lstn_addr.sin_family = AF_INET;
	lstn_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	lstn_addr.sin_port = htons(PORT);

	if (bind(lstn, (struct sockaddr *)&lstn_addr, sizeof(lstn_addr)) < 0) {
		perror("bind");
		return 1;
	}

	if (listen(lstn, 10) < 0) {
		perror("listen");
		return 1;
	}
	printf("Listening on port %d\n", PORT);

	signal(SIGCHLD, SIG_IGN);

	for (;;) {
		int con = accept(lstn, NULL, NULL);
		if (con < 0) {
			perror("accept");
			return 1;
		}

		switch (fork()) {
		case -1:
			perror("fork");
			return 1;
		case 0:
			printf("New connection, child %d\n", getpid());
			fflush(stdout);

			close(0);
			if (dup(con) < 0)
				exit(1);
			close(1);
			if (dup(con) < 0)
				exit(1);
			close(2);
			if (dup(con) < 0)
				exit(1);
			close(con);
			child();
			exit(0);
			break;
		default:
			close(con);
			break;
		}
	}
	return 0;
}
#include <stdio.h>

#define BUFSZ 1024

int printflag()
{
	char buf[BUFSZ], *scan = buf;

	FILE *flag = fopen("flag.txt", "r");
	if (flag == NULL) {
		perror("flag.txt");
		return -1;
	}

	if (fgets(buf, BUFSZ, flag) == NULL) {
		perror("flag.txt");
		return -1;
	}

	printf("Here is the flag:\n");
	while (*scan)	
		printf("%c", *scan++);

	fflush(stdout);
	return 0;
}
