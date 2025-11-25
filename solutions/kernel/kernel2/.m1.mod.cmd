cmd_/home/studenti/kernel/m1.mod := printf '%s\n'   m1.o | awk '!x[$$0]++ { print("/home/studenti/kernel/"$$0) }' > /home/studenti/kernel/m1.mod
