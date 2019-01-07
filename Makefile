#
#  3snake 0.01b - Linux string dumping from sshd, sudo, (su)
#  ---------------------------------------------------
#  Copyright (C) 2018 by Brendon Tiszka <brendon@tiszka.com>
#
#  Licensed under terms and conditions of MIT License
#

CFLAGS = -Wall -O9
CC     = gcc

PROG = 3snake
ASAN = 3snake-asan
FUZZ = 3snake-fuzz
OBFU = 3snake-obfu

OBJS = src/procinfo.o src/sudo_tracer.o src/su_tracer.o src/ssh_tracer.o src/ssh_client_tracer.o src/tracers.o src/main.o src/plisten.o

all: $(PROG)
$(PROG): $(OBJS)
	$(CC) $(OBJS) -o $(PROG)

asan:
	clang -fsanitize=address -Isrc src/tracers.c src/procinfo.c src/main.c src/su_tracer.c src/ssh_tracer.c src/sudo_tracer.c src/ssh_client_tracer.c src/plisten.c -o $(ASAN)

fuzz:
	clang++ -g -fsanitize=address -fsanitize-coverage=trace-pc-guard src/fuzz/tracers_fuzzer.cc -Isrc src/procinfo.c src/tracers.c src/ssh_tracer.c src/sudo_tracer.c src/su_tracer.c src/ssh_client_tracer.c ${LIBFUZZER_PATH} -o $(FUZZ)

obfuscate:
	${LLVM_OBFUSCATE_CLANG} -Isrc src/procinfo.c src/main.c src/plisten.c src/tracers.c src/sudo_tracer.c src/su_tracer.c src/ssh_tracer.c src/ssh_client_tracer.c -o $(OBFU) -mllvm -sub -mllvm -fla -mllvm -bcf

clean:
	rm -f $(PROG) $(ASAN) $(FUZZ) $(OBFU) $(OBJS) crash-* leak-* fuzz-* oom-*
