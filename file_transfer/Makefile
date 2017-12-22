CC=cc
LD=${CC}

CPPFLAGS=
CFLAGS=-Wall -g -std=gnu99 -fstack-protector-all
LDFLAGS=-Wl,-rpath,'.'
LDLIBS= -lnsl -lresolv -lpthread

all: encrypt.h server

clean:
	rm -f server server.o
