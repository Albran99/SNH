void usefulGadgets()
{
	asm ("addq %rdi, (%r15); ret");
}

void child()
{
	char buf[32];

	read(0, buf, 512);
}
