/*
* test_bench_kem.c - KEM 알고리즘 성능 측정용
*
* [구현 특성]
* - CLEAN (Non-AVX2) 구현 - 하드웨어 SIMD 가속 없이 순수 C 코드로 동작
* - PQClean 기준: 함수명에 _CLEAN_ 포함 (AVX2라면 _AVX2_ 로 표기됨)
* - 벤치마크 결과는 AVX2 최적화 버전 대비 보통 2~5배 느림
*
* [컴파일 방법] - 각 알고리즘 디렉터리에서 실행
*
*  ML-KEM-512:
*    gcc -O3 -I. -I../../../common \
*        cbd.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c symmetric-shake.c verify.c \
*        ../../../common/fips202.c ../../../common/randombytes.c \
*        test_bench_kem.c -o test_bench_kem
*
*  NTRU+576 / SMAUG-T (api.h에 short generic 이름 사용하는 경우):
*    -> 각 Makefile 참고해서 소스파일 목록 확인 후 동일 패턴으로 컴파일
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "kem.h"

#define BENCH_PK_BYTES  PUBLICKEY_BYTES 
#define BENCH_SK_BYTES  KEM_SECRETKEY_BYTES
#define BENCH_CT_BYTES  CIPHERTEXT_BYTES
#define BENCH_SS_BYTES  CRYPTO_BYTES
#define BENCH_ALGNAME   "smaug-t5"

#define BENCH_KEYPAIR(pk, sk)       crypto_kem_keypair(pk, sk)
#define BENCH_ENC(ct, ss, pk)       crypto_kem_encap(ct, ss, pk)
#define BENCH_DEC(ss, ct, sk, pk)   crypto_kem_decap(ss, sk, pk, ct)

static double elapsed_ms(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1000.0
         + (e.tv_nsec - s.tv_nsec) / 1e6;
}

int main(void) {
    int ITERATIONS = 1000; 

    uint8_t pk[BENCH_PK_BYTES];
    uint8_t sk[BENCH_SK_BYTES];
    uint8_t ct[BENCH_CT_BYTES];
    uint8_t ss_enc[BENCH_SS_BYTES];
    uint8_t ss_dec[BENCH_SS_BYTES];

    struct timespec t0, t1;
    int i;

    printf("=============================================================\n");
    printf(" Algorithm : %s\n", BENCH_ALGNAME);
    printf(" Implementation : CLEAN (Non-AVX2, pure C)\n");
    printf(" Iterations : %d\n", ITERATIONS);
    printf("=============================================================\n\n");

    /* ---- 1. KeyGen ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        if (BENCH_KEYPAIR(pk, sk) != 0) {
            fprintf(stderr, "KeyGen failed at iteration %d\n", i);
            return 1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double keygen_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- 2. Encap ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        if (BENCH_ENC(ct, ss_enc, pk) != 0) {
            fprintf(stderr, "Encap failed at iteration %d\n", i);
            return 1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double encap_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- 3. Decap ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        if (BENCH_DEC(ss_dec, ct, sk, pk) != 0) {
            fprintf(stderr, "Decap failed at iteration %d\n", i);
            return 1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double decap_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- 정확성 확인 ---- */
    int ss_ok = (memcmp(ss_enc, ss_dec, BENCH_SS_BYTES) == 0);

    /* ---- 결과 출력 ---- */
    printf("[Size]\n");
    printf("  pk_bytes : %d\n", BENCH_PK_BYTES);
    printf("  sk_bytes : %d\n", BENCH_SK_BYTES);
    printf("  ct_bytes : %d\n", BENCH_CT_BYTES);
    printf("  ss_bytes : %d\n", BENCH_SS_BYTES);
    printf("\n");
    printf("[Performance (avg over %d runs)]\n", ITERATIONS);
    printf("  KeyGen : %.4f ms\n", keygen_ms);
    printf("  Encap  : %.4f ms\n", encap_ms);
    printf("  Decap  : %.4f ms\n", decap_ms);
    printf("\n");
    printf("[Correctness]\n");
    printf("  Shared secret match : %s\n", ss_ok ? "OK" : "FAIL");
    printf("=============================================================\n");

    return ss_ok ? 0 : 1;
}