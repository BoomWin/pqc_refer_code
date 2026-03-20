#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "api.h"
#include "kem.h"
#include "parameters.h"

// 바이트 배열 출력 함수
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t pk[PUBLICKEY_BYTES];
    uint8_t sk[KEM_SECRETKEY_BYTES];
    uint8_t ct[CIPHERTEXT_BYTES];
    uint8_t ss1[CRYPTO_BYTES];
    uint8_t ss2[CRYPTO_BYTES];

    printf("SMAUG-T1 KEM Test\n");

    // 키 생성
    crypto_kem_keypair(pk, sk);
    printf("KeyPair Generated\n");
    // 중간 중간 생성된 값들에 대해서 체크 
    print_hex("pk", pk, PUBLICKEY_BYTES);
    print_hex("sk", sk, KEM_SECRETKEY_BYTES);


    // 캡슐화
    crypto_kem_encap(ct, ss1, pk);
    printf("Encapsulation Done!!\n");
    print_hex("ct", ct, CIPHERTEXT_BYTES);
    print_hex("ss1", ss1, CRYPTO_BYTES);

    // 디캡슐화
    crypto_kem_decap(ss2, sk, pk, ct);
    printf("Decapsulation Done!!\n");
    print_hex("ss2", ss2, CRYPTO_BYTES);


    // 검증
    if (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) {
        printf("[SUCCESS] : Share Secrets Match ! \n");
        return 0;
    }
    else {
        printf("[FAIL] : Share Secrets Unmatch ! \n");
        return -1;
    }
}