CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -O2
CXXFLAGS = -Wall -Wextra -O2

TARGETS = basic raii inline_check

all: $(TARGETS)

basic: basic.c ../snare.h
	$(CC) $(CFLAGS) -o $@ $<

raii: raii.cpp ../snare.h
	$(CXX) $(CXXFLAGS) -o $@ $<

inline_check: inline_check.c ../snare.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
