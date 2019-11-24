CC=gcc

all: pam_sqlite.so

pam_sqlite.so: sqlite3.c pam_sqlite.c
	$(CC) -shared  -lpam -ldl -pthread -o pam_sqlite.so -fpic sqlite3.c pam_sqlite.c

install: pam_sqlite.so
	cp pam_sqlite.so /lib/x86_64-linux-gnu/security/
clean:
	rm *.so *~
