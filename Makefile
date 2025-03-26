CC = gcc
CFLAGS = -Wall -O2
BPF_CFLAGS = -I/usr/include -I/usr/include/x86_64-linux-gnu -g -O2 -D__KERNEL__ -D__BPF_TRACING__ -Wall

all: ssh-audit bpf

ssh-audit: src/main.c
	$(CC) $(CFLAGS) -o ssh-audit src/main.c -lbpf

bpf: src/bpf_prog.c
	clang $(BPF_CFLAGS) -target bpf -c src/bpf_prog.c -o bpf_prog.o

clean:
	rm -f ssh-audit bpf_prog.o

run: all
	sudo ./ssh-audit
