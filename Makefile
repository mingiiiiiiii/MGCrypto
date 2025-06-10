# Top-level Makefile

CC = gcc
CFLAGS = -Iinclude -Iblockcipher -Ihash -Imac -Wall -Wextra -O2 -MMD -MP -fPIC
LDFLAGS =

# 디렉토리 설정
TEST_DIR = test
BUILD_DIR = lib

# 테스트 실행파일 목록
TEST_TARGETS = \
	$(TEST_DIR)/blockcipher_test \
	$(TEST_DIR)/hash_test \
	$(TEST_DIR)/hmac_test

# 동적 라이브러리 설정
LIB_NAME = $(BUILD_DIR)/libmgcrypto.so
LIB_SRCS = \
	blockcipher/mg_blockcipher.c \
	blockcipher/mg_aes.c \
	blockcipher/mg_aria.c \
	blockcipher/mg_lea.c \
	blockcipher/mg_gcm.c \
	hash/mg_hash.c \
	hash/mg_sha2.c \
	hash/mg_sha3.c \
	hash/mg_lsh512.c \
	mac/mg_hmac.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

# .o는 중간 산출물이므로 자동 삭제
.INTERMEDIATE: $(LIB_OBJS)

# 의존성 파일 자동 포함 (.d)
-include $(wildcard *.d */*.d)

.PHONY: all test clean

# 전체 빌드
all: $(TEST_TARGETS) $(LIB_NAME)

test: $(TEST_TARGETS)

# 테스트 바이너리들
$(TEST_DIR)/blockcipher_test:
	@mkdir -p $(TEST_DIR)
	$(CC) $(CFLAGS) -o $@ \
		blockcipher/mg_blockcipher_test.c \
		blockcipher/mg_blockcipher.c \
		blockcipher/mg_aes.c \
		blockcipher/mg_aria.c \
		blockcipher/mg_lea.c \
		$(LDFLAGS)

$(TEST_DIR)/hash_test:
	@mkdir -p $(TEST_DIR)
	$(CC) $(CFLAGS) -o $@ \
		hash/mg_hash_test.c \
		hash/mg_hash.c \
		hash/mg_sha2.c \
		hash/mg_sha3.c \
		hash/mg_lsh512.c \
		$(LDFLAGS)

$(TEST_DIR)/hmac_test:
	@mkdir -p $(TEST_DIR)
	$(CC) $(CFLAGS) -o $@ \
		mac/mg_hmac_test.c \
		mac/mg_hmac.c \
		hash/mg_sha2.c \
		$(LDFLAGS)

# 동적 라이브러리
$(LIB_NAME): $(LIB_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) -fPIC -shared -o $@ $^

# 정리
clean:
	rm -f $(LIB_NAME)
	rm -rf $(TEST_DIR) $(BUILD_DIR)
	find . \( -name "*.o" -o -name "*.d" \) -delete
