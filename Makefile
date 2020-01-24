CC=gcc
ASM=nasm
INSTALL=/lib
CFLAGS+= -Wall -ldl -o rk.so -fPIC -shared -D_GNU_SOURCE
ASMFLAGS+= -f elf64

all: father fix

father: father.c
	$(CC) $(CFLAGS) father.c

fix: remove_preload.asm
	$(ASM) $(ASMFLAGS) remove_preload.asm
	ld remove_preload.o -o fix.bin
clean:
	rm -f *.o *.so *.bin
	unset LD_PRELOAD
	
