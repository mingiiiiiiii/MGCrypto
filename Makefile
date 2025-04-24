# Top-level Makefile

CC = gcc
CFLAGS = -Iinclude -Iblockcipher -Wall -Wextra -O2 -MMD -MP
LDFLAGS =

# Test targets
TARGETS = blockcipher_test
DEPS = $(TARGETS:=.d)

.PHONY: all clean

all: $(TARGETS)

blockcipher_test: \
    blockcipher/mg_blockcipher_test.c \
    blockcipher/mg_blockcipher.c \
    blockcipher/mg_aes.c \
    blockcipher/mg_aria.c \
    blockcipher/mg_lea.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

-include $(DEPS)

clean:
	rm -f $(TARGETS) *.d
