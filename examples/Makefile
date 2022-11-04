CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -O2
CXXFLAGS = -Wall -Wextra -O2

TARGETS = inline_basic inline_raii inline_read inline_asm plt_basic plt_enum

all: $(TARGETS)

inline_basic: inline_basic.c ../libsnare.h
	$(CC) $(CFLAGS) -o $@ $<

inline_raii: inline_raii.cpp ../libsnare.h
	$(CXX) $(CXXFLAGS) -o $@ $<

inline_read: inline_read.c ../libsnare.h
	$(CC) $(CFLAGS) -o $@ $<

inline_asm: inline_asm.S inline_asm_impl.c ../libsnare.h
	$(CC) $(CFLAGS) -o $@ inline_asm.S inline_asm_impl.c

plt_basic: plt_basic.c ../libsnare.h
	$(CC) $(CFLAGS) -o $@ $< -ldl

plt_enum: plt_enum.c ../libsnare.h
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f $(TARGETS)

.PHONY: all clean
