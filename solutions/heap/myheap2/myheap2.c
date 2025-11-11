#define BUFSZ 32
char* values[256];
int lengths[256];
void createkey(unsigned char key)
{
	char len[2];
	char *v;
	int n;

	if (read(0, len, 2) < 2) {
		fprintf(stderr, "error reading key length\n");
		return;
	}
	if (len[0] < '0' || len[0] > '9' || len[1] < '0' || len[1] > '9') {
		fprintf(stderr, "invalid length: %c%c\n", len[0], len[1]);
		return;
	}
	n = (len[0] - '0') * 10 + (len[1] - '0');
	v = malloc(n);
	if (v == NULL) {
		fprintf(stderr, "out of memory\n");
		return;
	}
	lengths[key] = n;
	if (values[key] != NULL)
		free(values[key]);
	values[key] = v;
}
void assignkey(unsigned char key)
{
	int n;
	char *v;

	if (values[key] == NULL) {
		fprintf(stderr, "no such key\n");
		return;
	}

	n = read(0, values[key], lengths[key]);
	if (n <= 0) {
		fprintf(stderr, "Error/EOF while reading value\n");
		return;
	}
}

void deletekey(unsigned char key)
{
	char *v = values[key];

	if (v == NULL) {
		fprintf(stderr, "No such key: %c\n", key);
		return;
	}
	free(v);
}

void searchkey(unsigned char key)
{
	int n;
	char *v;

	if (values[key] == NULL) {
		fprintf(stderr, "no such key\n");
		return;
	}
	n = lengths[key];
	v = values[key];
	while (n > 0) {
		int m = write(1, v, n);
		if (m < 0) {
			fprintf(stderr, "error sending key value\n");
			return;
		}
		n -= m;
		v += m;
	}
}

void child()
{
	char cmd;
	while (read(0, &cmd, 1) > 0) {
		unsigned char key;
		if (cmd != 'c' && cmd != 'a' && cmd != 'd' && cmd != 's' && cmd != 'q') {
			if (cmd != '\n')
				fprintf(stderr, "Unknown command: '%c'\n", cmd);
			continue;
		}
		if (cmd == 'q')
			break;
		if (read(0, &key, 1) <= 0) {
			fprintf(stderr, "Error/EOF while reading key\n");
			return;
		}
		switch (cmd) {
		case 'c':
			createkey(key);
			break;
		case 'a':
			assignkey(key);
			break;
		case 'd':
			deletekey(key);
			break;
		case 's':
			searchkey(key);
			break;
		default:
			break;
		}
	}
}
