#define _POSIX_C_SOURCE 200809L

/*
* test_bench_dsa_combined.c
* 대상: AIMer (crypto_sign / crypto_sign_open 방식)
*
* AIMer는 detached API가 없고 combined(서명+메시지 합쳐서 출력)만 있음
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "api.h"

#define BENCH_PK_BYTES  CRYPTO_PUBLICKEYBYTES
#define BENCH_SK_BYTES  CRYPTO_SECRETKEYBYTES
#define BENCH_SIG_BYTES CRYPTO_BYTES   /* 순수 서명 크기 (메시지 제외) */
#define BENCH_ALGNAME   CRYPTO_ALGNAME

static double elapsed_ms(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1000.0
         + (e.tv_nsec - s.tv_nsec) / 1e6;
}

int main(void) {
    int ITERATIONS = 1000;
    int MSG_LEN = 32;

    uint8_t pk[BENCH_PK_BYTES];
    uint8_t sk[BENCH_SK_BYTES];

    /* combined: sm 버퍼는 메시지 + 서명 크기 */
    uint8_t *sm = malloc(MSG_LEN + BENCH_SIG_BYTES);
    uint8_t *m_out = malloc(MSG_LEN + BENCH_SIG_BYTES);
    unsigned long long smlen = 0, mlen_out = 0;

    uint8_t msg[32];
    memset(msg, 0xAB, sizeof(msg));

    struct timespec t0, t1;
    int i;

    printf("=============================================================\n");
    printf(" Algorithm : %s\n", BENCH_ALGNAME);
    printf(" Implementation : CLEAN (Non-AVX2, pure C)\n");
    printf(" Iterations : %d\n", ITERATIONS);
    printf("=============================================================\n\n");

    /* ---- KeyGen ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        crypto_sign_keypair(pk, sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double keygen_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- Sign ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        crypto_sign(sm, &smlen, msg, MSG_LEN, sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sign_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- Verify (sign_open) ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        crypto_sign_open(m_out, &mlen_out, sm, smlen, pk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double verify_ms = elapsed_ms(t0, t1) / ITERATIONS;

    printf("[Size]\n");
    printf("  pk_bytes  : %d\n", BENCH_PK_BYTES);
    printf("  sk_bytes  : %d\n", BENCH_SK_BYTES);
    printf("  sig_bytes : %d\n", BENCH_SIG_BYTES);
    printf("\n");
    printf("[Performance (avg over %d runs)]\n", ITERATIONS);
    printf("  KeyGen : %.4f ms\n", keygen_ms);
    printf("  Sign   : %.4f ms\n", sign_ms);
    printf("  Verify : %.4f ms\n", verify_ms);
    printf("=============================================================\n");

    free(sm);
    free(m_out);
    return 0;
}