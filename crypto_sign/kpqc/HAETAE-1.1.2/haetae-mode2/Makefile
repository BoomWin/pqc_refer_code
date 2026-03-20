# HAETAE Mode 2 (haetae-120, Level 2)
CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c11

# 소스 경로
SOURCES = decompose.c encoding.c fft.c fixpoint.c ntt.c packing.c \
            poly.c polyvec.c polymat.c polyfix.c reduce.c sampler.c \
            sign.c randombytes.c fips202.c symmetric-shake.c

# Node.js 연결 위한 실행 파일
pqc_cli: $(SOURCES) pqc_cli.c
		$(CC) $(CFLAGS) -o $@ $^ -lm

test_bench_dsa: $(SOURCES) test_bench_dsa.c
		$(CC) $(CFLAGS) -o $@ $^ -lm

clean:
	rm -f pqc_cli