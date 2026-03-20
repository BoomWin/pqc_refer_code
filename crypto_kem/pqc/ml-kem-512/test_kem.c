#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "api.h"

// 바이트 배열 출력
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    printf("=== ML-KEM 512 Test == \n\n");

    // 키 생성
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    printf("KeyPair Generation \n");
    print_hex("pk", pk, sizeof(pk));
    print_hex("sk", sk, sizeof(sk));

    // 캡슐화 테스트
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, pk);
    printf("\n Encapsulation Done \n");
    print_hex("ct", ct, sizeof(ct));
    print_hex("ss1", ss1, sizeof(ss1));

    // 디캡슐 테스트
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);
    print_hex("ss2", ss2, sizeof(ss2));

    // 검증
    printf("\n");
    if (memcmp(ss1, ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES) == 0) {
        printf("[SUCCESS] Shared Secrets match !!! \n");
        return 0;
    }
    else {
        printf("[FAILED] Share secrets Unmatched !! \n");
        return -1;
    }
}