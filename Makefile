CLANG ?= clang
CC ?= gcc
LIBBPF ?= /usr/include

override CFLAGS += -O2 -g -Wall
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

all: ddosguard ddosguard.bpf.o

ddosguard.bpf.o: bpf/ddosguard.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -Ibpf -c bpf/ddosguard.bpf.c -o ddosguard.bpf.o

ddosguard.skel.h: ddosguard.bpf.o
	bpftool gen skeleton ddosguard.bpf.o > ddosguard.skel.h

ddosguard: src/ddosguard.c ddosguard.skel.h
	$(CC) $(CFLAGS) -I$(LIBBPF) -I. src/ddosguard.c -o ddosguard -lbpf -lelf -lz

clean:
	rm -f ddosguard ddosguard.bpf.o ddosguard.skel.h

install: ddosguard
	install -d /opt/ddosguard
	install -m 0755 ddosguard /opt/ddosguard/ddosguard
	install -m 0644 ddosguard.bpf.o /opt/ddosguard/ddosguard.bpf.o

.PHONY: all clean install