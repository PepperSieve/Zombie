
CC=g++ -g
CCFLAGS=--ansi -W -Wall -Wno-unused-parameter -Wno-register -std=c++17 -lgmpxx -lgmp

SRCS=$(wildcard src/**/*.C)
HDRS=$(wildcard src/**/*.H)
OBJS=$(patsubst src/%.C,bin/%.o,$(SRCS))

all : bin/TestRegex

bin/TestRegex : ${OBJS} src/Test.C
	@echo "Linking TestRegex..."
	$(CC) $^ $(CCFLAGS) -o $@

bin/%.o : src/%.C $(HEADERS)
	@mkdir -p $(shell dirname $@)
	$(CC) $< $(CCFLAGS) -c -o $@

clean :
	rm -r bin/*