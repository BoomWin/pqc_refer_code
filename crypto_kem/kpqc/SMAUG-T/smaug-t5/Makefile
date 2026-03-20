# SMAUG-T5

CC = gcc
CFLAGS = -O3 -Wall -Wextra

SOURCES = ciphertext.c dg.c fips202.c hash.c hwt.c indcpa.c \
			io.c kem.c key.c pack.c poly.c randombytes.c verify.c

# 테스트 실행파일 빌드
# 기존 SMAUG makefile도 -lcrypto 사용함. 
test_kem_t5 : $(SOURCES) test_smaug_t5_kem.c
	$(CC) $(CFLAGS) -o $@ $^ 
	
test_bench: $(SOURCES) test_bench_kem.c
	$(CC) $(CFLAGS) -o $@ $^

	
# $(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto
# MAKE 파일 수정 영역,.. (원래와 다른 부분)
pqc_cli: $(SOURCES) pqc_cli.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f test_kem pqc_cli