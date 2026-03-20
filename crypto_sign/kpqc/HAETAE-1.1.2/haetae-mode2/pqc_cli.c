/**
 HAETAE CLI Wrapper - Node.js 적용하기 위함

사용 명령어
    ./pqc_cli keygen
    ./pqc_cli keygen_derand <seed_hex>
    ./pqc_cli sign <sk_hex> <message_hex>
    ./pqc_cli verify <pk_hex> <message_hex> <sig_hex>
*/

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

// 상수 정의 
#define PK_BYTES CRYPTO_PUBLICKEYBYTES   // Mode2: 992, Mode3: 1472, Mode5: 2080
#define SK_BYTES CRYPTO_SECRETKEYBYTES   // Mode2: 1408, Mode3: 2112, Mode5: 2752
#define SIG_BYTES CRYPTO_BYTES           // Mode2: 1474, Mode3: 2349, Mode5: 2948
#define SEED_BYTES 32                    // HAETAE_SEEDBYTES (모든 모드 동일)

// Hex ===> Bytes 변환
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }
    return 0;
}

// Bytes ===> Hex 변환 (동적 할당)
char* bytes_to_hex(const uint8_t *bytes, size_t len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

// 에러 출력 (JSON 형식)
void print_error(const char *msg) {
    printf("{\"error\":\"%s\"}\n", msg);
}

/*=====================================================================
* KEYGEN : 키 쌍 생성 (랜덤)
*======================================================================*/
int do_keygen(void) {
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];

    if (crypto_sign_keypair(pk, sk) != 0) {
        print_error("키 생성 실패 ...");
        return 1;
    }

    char *pk_hex = bytes_to_hex(pk, PK_BYTES);
    char *sk_hex = bytes_to_hex(sk, SK_BYTES);

    if(!pk_hex || !sk_hex) {
        print_error("메모리 할당 실패 ...");
        free(pk_hex);
        free(sk_hex);
        return 1;
    }

    printf("{\"pk\":\"%s\",\"sk\":\"%s\"}\n", pk_hex, sk_hex);

    free(pk_hex);
    free(sk_hex);
    return 0;
}

/*=====================================================================
* [INPUT] KEYGEN : 키 쌍 생성 (seed 값을 input으로 받아서)
*======================================================================*/
int do_keygen_derand(const char *seed_hex) {
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];
    uint8_t seed[SEED_BYTES];

    if (hex_to_bytes(seed_hex, seed, SEED_BYTES) != 0) {
        print_error("유효하지 않은 seed HEX (64자 필요)");
        return 1;
    }

    if (crypto_sign_keypair_internal(pk, sk, seed) != 0) {
        print_error("keygen_derand failed");
        return 1;
    }

    char *pk_hex = bytes_to_hex(pk, PK_BYTES);
    char *sk_hex = bytes_to_hex(sk, SK_BYTES);

    if (!pk_hex || !sk_hex) {
        print_error("메모리 할당 실패");
        free(pk_hex);
        free(sk_hex);
        return 1;
    }

    printf("{\"pk\":\"%s\",\"sk\":\"%s\"}\n", pk_hex, sk_hex);

    free(pk_hex);
    free(sk_hex);
    return 0;
}

/*=====================================================================
* SIGN : 개인키로 메시지 서명
*======================================================================*/
int do_sign(const char *sk_hex, const char *msg_hex) {
    uint8_t sk[SK_BYTES];
    uint8_t sig[SIG_BYTES];
    size_t siglen = 0;

    if (hex_to_bytes(sk_hex, sk, SK_BYTES) != 0) {
        print_error("유효하지 않은 SK HEX 값");
        return 1;
    }

    // 메시지 길이 계산 및 변환
    size_t msg_len = strlen(msg_hex)/2;
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        print_error("메모리 할당 실패");
        free(msg);
        return 1;
    }
    if (hex_to_bytes(msg_hex, msg, msg_len) != 0 ){
        print_error("유효하지 않은 Message hex 값");
        free(msg);
        return 1;
    }

    // 서명 수행 (ctx = NULL, ctxlen = 0)
    if (crypto_sign_signature(sig, &siglen, msg, msg_len, NULL, 0, sk) != 0){
        print_error("SIGN 실패 ...");
        free(msg);
        return 1;
    }

    char *sig_hex = bytes_to_hex(sig, siglen);

    if (!sig_hex) {
        print_error("메모리 할당 실패 ");
        free(msg);
        return 1;
    }

    printf("{\"sig\":\"%s\",\"siglen\":%zu}\n", sig_hex, siglen);

    free(sig_hex);
    free(msg);
    return 0;
}

/*=====================================================================
* VERIFY : 공개키로 서명 검증
*======================================================================*/
int do_verify(const char *pk_hex, const char *msg_hex, const char *sig_hex) {
    uint8_t pk[PK_BYTES];
    uint8_t sig[SIG_BYTES];

    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효하지 않은 PK HEX 값");
        return 1;
    }

    if (hex_to_bytes(sig_hex, sig, SIG_BYTES) != 0) {
        print_error("유효하지 않은 signature HEX 값");
        return 1;
    }

    // 메시지 변환
    size_t msg_len = strlen(msg_hex) / 2;
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        print_error("메모리 할당 실패");
        return 1;
    }
    if (hex_to_bytes(msg_hex, msg, msg_len) != 0) {
        print_error("유효하지 않은 message HEX 값");
        free(msg);
        return 1;
    }

    // 검증 수행 (ctx = NULL, ctxlen = 0)
    int result = crypto_sign_verify(sig, SIG_BYTES, msg, msg_len, NULL, 0, pk);

    printf("{\"valid\":%s}\n", result == 0 ? "true" : "false");

    free(msg);
    return 0;
}

/*=====================================================================
* MAIN 명령어 파싱 및 실행
*======================================================================*/
int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_error("사용 방법 : pqc_cli <keygen|sign|verify> [args ...]");
        return 1;
    }

    const char *cmd = argv[1];

    // keygen 명령
    if (strcmp(cmd, "keygen") == 0) {
        return do_keygen();
    }

    // keygen 수동 입력 명령
    if (strcmp(cmd, "keygen_derand") == 0) {
        if (argc < 3) {
            print_error("사용 방법 : pqc_cli keygen_derand <seed_hex 64자>");
            return 1;
        }
        return do_keygen_derand(argv[2]);
    }

    // sign 명령
    if (strcmp(cmd, "sign") == 0) {
        if (argc < 4) {
            print_error("사용 방법 : pqc_cli sign <sk_hex> <message_hex>");
            return 1;
        }
        return do_sign(argv[2], argv[3]);
    }

    // verify 명령
    if (strcmp(cmd, "verify") == 0) {
        if (argc < 5) {
            print_error("사용 방법 : pqc_cli verify <pk_hex> <message_hex> <sig_hex>");
            return 1;
        }
        return do_verify(argv[2], argv[3], argv[4]);
    }

    print_error("유효하지 않은 명령어");
    return 1;
}

// 지금 현재는 key 관련된것만 랜덤 / 비랜덤으로 구성했는데 
// API 분석해보니까 Sign 과 Verify 관련된것도 존재하는데 internal 함수로 그게 먼지 나중ㅇ ㅔ분석 및 추가.