all: ELFdebugger

CC = gcc
CFLAGS = -ljson-c -lcapstone
ELFdebugger: debugger.cpp
	$(CC) -o ELFdebugger debugger.cpp $(CFLAGS)


.PHONY: clean,run
clean:
	rm ELFdebugger

run:
	./ELFdebugger ./sampleProgram/sample test

runs:
	 ./ELFdebugger ./sampleProgram/sample1 123
