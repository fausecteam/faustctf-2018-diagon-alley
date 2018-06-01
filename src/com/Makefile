CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -D_FORTIFY_SOURCE=2 -O3 -fPIC -fstack-protector-all -pie -DTFM_DESC  -DLTC_PKCS_1 -s
CPPFLAGS = -DTFM_DESC
LDFLAGS = -static -L../com/libtomcrypt -L../com/tomsfastmath
LIBS = -ltomcrypt -ltfm

.PHONY: all clean

all: networking.o crypto.o tomcrypt tfm

%.o: %.c %.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(LDFLAGS) -o $@ $<  $(LIBS)

tomcrypt:
	$(MAKE) -C libtomcrypt CFLAGS="-DUSE_TFM -DTFM_DESC" EXTRALIBS="-ltfm"

tfm:
	$(MAKE) -C tomsfastmath

clean:
	rm -f *.o
	$(MAKE) -C libtomcrypt clean
	$(MAKE) -C tomsfastmath clean
