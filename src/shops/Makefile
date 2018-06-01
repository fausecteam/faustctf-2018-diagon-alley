#CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -D_FORTIFY_SOURCE=2 -O3 -fPIC -fstack-protector-all -pie -s
CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -fno-stack-protector -s
LIBS = -lsqlite3 -lseccomp

.PHONY: all clean

all: shops

shops: shops.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	strip $@

clean:
	rm -f shops *.o *.db
