#include <stdio.h>
#include <stdlib.h>

#include "../common/printflag.c"

#define MYBUF 100
char buf[MYBUF];
int admin = 0;

int main(int argc, char *argv[])
{
	int i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <number>\n", argv[0]);
		exit(1);
	}

	i = atoi(argv[1]);
	if (i >= MYBUF) {
		fprintf(stderr, "out of bounds\n");
		exit(1);
	}
	buf[i] = 1;

	if (admin)
		printflag();

}
