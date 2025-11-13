void vuln(size_t s)
{
	char * a = malloc(s);
	char * b = malloc(s);

	printf("a %p b %p\n", a, b);

	read(0, a, s + 1);

	free(b);
	puts("OK");
	free(a);
}
void child()
{
	vuln(264);
}
