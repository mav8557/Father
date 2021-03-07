CC=gcc
ASM=nasm
SDIR=src
ODIR=bin
IDIR=$(SDIR)
INSTALL=/lib
CFLAGS+= -Wall -fPIC -shared -D_GNU_SOURCE
LFLAGS=-ldl
ASMFLAGS+= -f elf64
_OBJS = accept.o access.o exec.o father.o open.o readdir.o stat.o unlink.o
OBJS = $(patsubst %,$(ODIR)/%, $(_OBJS))

all: father fix

$(ODIR)/%.o: $(SDIR)/%.c $(SDIR)/father.h
	$(CC) $(CFLAGS) -o $@ $< -c

father: $(OBJS)
	$(CC) $(CFLAGS) $^ -o rk.so $(LFLAGS)

fix: $(SDIR)/remove_preload.asm
	$(ASM) $(ASMFLAGS) $(SDIR)/remove_preload.asm -o $(ODIR)/remove_preload.o
	ld $(ODIR)/remove_preload.o -o fix.bin

clean:
	rm -f $(OBJS) *.so *.bin
	unset LD_PRELOAD
