#include <linux/limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#ifndef PORT
#define PORT 4471
#endif

#define MAXLINE 1024
#define ARGSZ 16
#define MAXOBJ 32

struct ArgObj {
	char arg[ARGSZ];
};

struct ExecObj {
	void (*run) (char *arg);
	int arg_pos;
	int arg_idx;
};

struct objentry {
	void *obj;
	unsigned long num;
};

struct objentry objects[MAXOBJ];

struct objentry do_newarg(const char *buf)
{
       	long num;
	unsigned long size;
	struct ArgObj *obj;
	struct objentry e = { NULL, 0 };

	if ( (num = atol(buf)) <= 0 ) {
		fprintf(stderr, "invalid number of argument objects\n");
		return e;
	}
	size = num * sizeof(*obj);
	if ( (obj = malloc(size)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return e;
	}
	memset(obj, 0, size);
	e.obj = obj;
	e.num = num;
	return e;
}

const char *parseref(const char *buf, int *ppos, int *pidx);
void ExecObj_Ctr_run(char *arg);
void ExecObj_Grep_run(char *arg);
struct objentry do_newexec(const char *buf)
{
	char subtype;
	struct ExecObj *obj;
	struct objentry e = { NULL, 0 }, *ar;

	if ( (obj = malloc(sizeof(*obj))) == NULL ) {
		fprintf(stderr, "out of memory\n");
		return e;
	}
	obj->arg_pos = obj->arg_idx = -1;
	subtype = *buf++;
	buf = parseref(buf, &obj->arg_pos, &obj->arg_idx);
	if (buf == NULL || *buf != '\0') {
		fprintf(stderr, "invalid argument reference\n");
		free(obj);
		return e;
	}
	switch (subtype) {
	case 'c':
		obj->run = ExecObj_Ctr_run;
		break;
	case 'g':
		obj->run = ExecObj_Grep_run;
		break;
	default:
		fprintf(stderr, "unknown exec subtype\n");
		free(obj);
		return e;
	}
	e.obj = obj;
	return e;
}

// NO INTENTIONAL BUGS AFTER THIS POINT

void ExecObj_Ctr_run(char *arg)
{
	int i;

	for (i = 0; i < ARGSZ && !isdigit(arg[i]); i++)
		;
	for ( ; i < ARGSZ; i++) {
		if (!isdigit(arg[i]))
			break;
	}
	if (i >= ARGSZ)
		return;
	for (i--; i >= 0 && isdigit(arg[i]); i--) {
		if (arg[i] < '9') {
			arg[i]++;
			break;
		}
		arg[i] = '0';
	}
}

void ExecObj_Grep_run(char *arg)
{
	char cmd[MAXLINE];
	int i;

	for (i = 0; i < ARGSZ && arg[i] != '\0'; i++) {
		if (!isalnum(arg[i])) {
			fprintf(stderr, "invalid search pattern\n");
			return;
		}
	}

	if (snprintf(cmd, MAXLINE, "grep '^%s$' data/*", arg) >= MAXLINE) {
		fprintf(stderr, "command too long\n");
		return;
	}
	if (system(cmd) < 0)
		fprintf(stderr, "command failed\n");
}

int findfree();
void do_newobj(const char *buf)
{
	int pos;
	char type, subtype;
	struct ArgObj *obj;

	pos = findfree();
	if (pos >= MAXOBJ) {
		fprintf(stderr, "full\n");
		return;
	}
	type = *buf++;
	if (type == '\0') {
		fprintf(stderr, "missing object type\n");
		return;
	}
	switch (type) {
	case 'a':
		objects[pos] = do_newarg(buf);
		break;
	case 'e':
		objects[pos] = do_newexec(buf);
		break;
	default:
		fprintf(stderr, "invalid type\n");
		free(obj);
		return;
	}
	if (objects[pos].obj != NULL)
		printf("%d\n", pos);
}

int findfree()
{
	struct objentry *e = NULL;
	int i = 0;
	for ( ; i < MAXOBJ; i++)
		if (!objects[i].obj)
			break;
	return i;
}

// expects buf to contain pos[,idx]. If valid,
// sets *ppos and *pidx to pos and idx, respectively.
// Returns a pointer to the first unparsed char, or
// NULL in case of error.
const char *parseref(const char *buf, int *ppos, int *pidx)
{
	char *rest;
	long long pos, idx;
	struct Obj *obj;

	if (*buf == '\0') {
		fprintf(stderr, "missing reference\n");
		return NULL;
	}
	errno = 0;
	pos = strtol(buf, &rest, 10);
	if (errno || pos < 0 || pos >= MAXOBJ) {
		fprintf(stderr, "reference out of range\n");
		return NULL;
	}
	if (rest == buf) {
		fprintf(stderr, "invalid input\n");
		return NULL;
	}
	buf = rest;
	obj = objects[pos].obj;
	if (obj == NULL) {
		fprintf(stderr, "invalid reference\n");
		return NULL;
	}
	*ppos = pos;
	idx = 0;
	if (*buf == ',') {
		buf++; // skip the comma
		if (*buf == '\0') {
			fprintf(stderr, "missing index\n");
			return NULL;
		}
		errno = 0;
		idx = strtoll(buf, &rest, 10);
		if (errno || idx < 0 || idx >= objects[pos].num) {
			fprintf(stderr, "array index out of range\n");
			return NULL;
		}
		if (rest == buf) {
			fprintf(stderr, "invalid input\n");
			return NULL;
		}
		buf = rest;
	}
	*pidx = idx;
	return buf;
}

void do_setarg(const char *buf)
{
	int pos, idx;
	struct ArgObj *obj;
	struct objentry *e;

	buf = parseref(buf, &pos, &idx);
	if (buf == NULL)
		return;
	e = &objects[pos];
	if (!e->num) {
		fprintf(stderr, "not an argument\n");
		return;
	}
	if (*buf != '=') {
		fprintf(stderr, "missing arg\n");
		return;
	}
	buf++;
	if (strlen(buf) >= ARGSZ) {
		fprintf(stderr, "string too long\n");
		return;
	}
	obj = e->obj;
	strncpy(obj[idx].arg, buf, ARGSZ);
}

void do_run(const char *buf)
{
	int pos, idx;
	struct ArgObj *argobj;
	struct ExecObj *execobj;
	struct objentry *e;

	buf = parseref(buf, &pos, &idx);
	if (buf == NULL)
		return;
	if (*buf != '\0') {
		fprintf(stderr, "invalid input\n");
		return;
	}
	e = &objects[pos];
	if (e->num) {
		argobj = e->obj;
		printf("%s\n", argobj[idx].arg);
	} else {
		execobj = e->obj;
		argobj = objects[execobj->arg_pos].obj;
		execobj->run(argobj[execobj->arg_idx].arg);
	}
}

void child(int uid)
{
	char buf[MAXLINE], *n;

	printf("Welcome to int3\n");

	for (;;) {
		if (fgets(buf, MAXLINE, stdin) == NULL)
			break;
		n = index(buf, '\n');
		if (n != NULL)
			*n = '\0';
		switch (buf[0]) {
		case '\0':
			break;
		case 'o':
			do_newobj(buf + 1);
			break;
		case 'a':
			do_setarg(buf + 1);
			break;
		case 'r':
			do_run(buf + 1);
			break;
		default:
			fprintf(stderr, "invalid command\n");
			break;
		}
	}
}

void sigchld(int signo)
{
	int status;
	pid_t pid = waitpid(-1, &status, WNOHANG);
	if (pid > 0) {
		printf("child %ld: ", (long)pid);
		if (WIFEXITED(status)) {
			printf("exited with status: %d\n", WEXITSTATUS(status));
		} else {
			printf("%s\n", strsignal(WTERMSIG(status)));
		}
	}
}

int main()
{
	int lstn;
	int enable;
	struct sockaddr_in lstn_addr;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

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

	signal(SIGCHLD, sigchld);

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

			close(0);
			if (dup(con) < 0)
				goto error;
			close(1);
			if (dup(con) < 0)
				goto error;
			close(2);
			if (dup(con) < 0)
				goto error;
			child(1);
			exit(0);
			break;
		default:
			close(con);
			break;
		}
	}
	return 0;

error:
	fprintf(stderr, "dup() failed\n");
	exit(1);
}
