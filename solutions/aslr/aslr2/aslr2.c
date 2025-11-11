#define LARGE_BUF 	512
#define MEDIUM_BUF	128
#define SMALL_BUF 	32

int myatoi(char *buf)
{
	int n = 0;
	while (*buf >= '0' && *buf <= '9') {
		n *= 10;
		n += *buf - '0';
		buf++;
	}
	return n;
}

void do_stuff(char *buf)
{
	char tmp[SMALL_BUF];
	int n;
       
        n = myatoi(buf);
	memcpy(tmp, buf, n);
}

void echo()
{
	char buf[MEDIUM_BUF];
	int n;

	if (read(0, buf, MEDIUM_BUF) < 0)
		return;
	write(1, buf, MEDIUM_BUF);
}

void child()
{
	char buf[LARGE_BUF];
	int n;

	for (;;) {
		n = read(0, buf, LARGE_BUF);
		if (n <= 0)
			return;
		if (buf[0] == '0') {
			echo();
		} else {
			do_stuff(buf);
		}
	}
}
