void child()
{
	char buf[32];
	int n;

	n = read(0, buf, 512);
	if (n < 0)
		return;
	write(1, buf, n);
}
