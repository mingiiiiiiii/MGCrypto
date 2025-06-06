# Top-level Makefile

CC = gcc
CFLAGS = -Iinclude -Iblockcipher -Wall -Wextra -O2 -MMD -MP
LDFLAGS =

# Test targets
TARGETS = blockcipher_test \
		  hash_test \
		  hmac_test
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

hash_test: \
	hash/mg_hash_test.c \
	hash/mg_hash.c \
	hash/mg_sha2.c \
	hash/mg_sha3.c \
	hash/mg_lsh512.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

hmac_test: \
	mac/mg_hmac_test.c \
	mac/mg_hmac.c \
	hash/mg_sha2.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

-include $(DEPS)

clean:
	rm -f $(TARGETS) *.d
