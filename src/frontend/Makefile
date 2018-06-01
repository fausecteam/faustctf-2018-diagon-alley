#CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -D_FORTIFY_SOURCE=2 -O3 -fPIC -fstack-protector-all -pie -I../com/ -I../shops -s
CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -fno-stack-protector -I../com/ -I../shops -s
LDFLAGS = -static -L../com/libtomcrypt/ -L../com/tomsfastmath/

OBJECTS = diagon_ally.o ../com/networking.o ../com/crypto.o
LIBS = -ltomcrypt -ltfm -lseccomp 
.PHONY: all clean

all: diagon_alley


diagon_ally.o: diagon_alley.c
	$(CC) -c $(CFLAGS) -o $@ $<

diagon_alley: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)
	strip $@

clean:
	rm -f *.o diagon_alley

