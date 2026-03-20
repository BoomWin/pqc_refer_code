#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"

/* HAETAE에서 ctx 파라미터가 추가됨 (NULL, 0 으로 패스하면 됨) */
#define BENCH_KEYPAIR(pk, sk)               crypto_sign_keypair(pk, sk)
#define BENCH_SIGN(sig, sl, m, ml, sk)      crypto_sign_signature(sig, sl, m, ml, NULL, 0, sk)
#define BENCH_VERIFY(sig, sl, m, ml, pk)    crypto_sign_verify(sig, sl, m, ml, NULL, 0, pk)

#define BENCH_PK_BYTES  CRYPTO_PUBLICKEYBYTES
#define BENCH_SK_BYTES  CRYPTO_SECRETKEYBYTES
#define BENCH_SIG_BYTES CRYPTO_BYTES
#define BENCH_ALGNAME   CRYPTO_ALGNAME

static double elapsed_ms(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1000.0
         + (e.tv_nsec - s.tv_nsec) / 1e6;
}

int main(void) {
    int ITERATIONS = 1000;

    uint8_t pk[BENCH_PK_BYTES];
    uint8_t sk[BENCH_SK_BYTES];
    uint8_t sig[BENCH_SIG_BYTES];
    size_t  siglen = 0;

    /* 고정 테스트 메시지 32바이트 */
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
        BENCH_KEYPAIR(pk, sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double keygen_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- Sign ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        BENCH_SIGN(sig, &siglen, msg, sizeof(msg), sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sign_ms = elapsed_ms(t0, t1) / ITERATIONS;

    /* ---- Verify ---- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < ITERATIONS; i++) {
        BENCH_VERIFY(sig, siglen, msg, sizeof(msg), pk);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double verify_ms = elapsed_ms(t0, t1) / ITERATIONS;

    printf("[Size]\n");
    printf("  pk_bytes  : %d\n", BENCH_PK_BYTES);
    printf("  sk_bytes  : %d\n", BENCH_SK_BYTES);
    printf("  sig_bytes : %zu\n", siglen);   /* 실제 서명 길이 */
    printf("  sig_bytes (max) : %d\n", BENCH_SIG_BYTES);
    printf("\n");
    printf("[Performance (avg over %d runs)]\n", ITERATIONS);
    printf("  KeyGen : %.4f ms\n", keygen_ms);
    printf("  Sign   : %.4f ms\n", sign_ms);
    printf("  Verify : %.4f ms\n", verify_ms);
    printf("=============================================================\n");

    return 0;
}