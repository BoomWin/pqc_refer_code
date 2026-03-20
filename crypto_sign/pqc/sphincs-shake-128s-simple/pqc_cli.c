/**
 SPHINCS+-SHAKE-???-simple CLI Wrapper - Node.js 적용하기 위함

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

// 상수 정의 - api.h 에서 가져옴
#define PK_BYTES PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES   
#define SK_BYTES PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES   
#define SIG_BYTES PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES           
#define SEED_BYTES PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SEEDBYTES     

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
    
    if (PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        print_error("키 생성 실패");
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
* [INPUT] KEYGEN : 키 쌍 생성 (seed 값을 input으로 받아서)
*======================================================================*/

int do_keygen_derand(const char *seed_hex) {
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];
    uint8_t seed[SEED_BYTES];

    if (hex_to_bytes(seed_hex, seed, SEED_BYTES) != 0) {
        print_error("유효하지 않은 seed HEX");
        return 1;
    }

    if (PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_seed_keypair(pk, sk, seed) != 0) {
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
* SIGN : 개인키로 메시지 서명 (Detached API)
*======================================================================*/

// 현재는 랜덤 seed 입력으로 안 받고 수행하게끔 구현되어 있는데
// 추후 우리가 개발한 걸 테스트하기 위해서는 seed 값도 재현가능하게끔 api 구현해야함. [추후 개발]
int do_sign(const char *sk_hex, const char *msg_hex) {
    uint8_t sk[SK_BYTES];
    uint8_t sig[SIG_BYTES];
    size_t siglen = 0;

    if (hex_to_bytes(sk_hex, sk, SK_BYTES) != 0) {
        print_error("유효하지 않은 SK HEX 값");
        return 1;
    }

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

    if (PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, &siglen, msg, msg_len, sk) != 0) {
        print_error("SIGN 실패");
        free(msg);
        return 1;
    }

    char *sig_hex = bytes_to_hex(sig, siglen);

    if (!sig_hex) {
        print_error("메모리 할당 실패");
        free(msg);
        return 1;
    }

    printf("{\"sig\":\"%s\",\"siglen\":%zu}\n", sig_hex, siglen);

    free(sig_hex);
    free(msg);
    return 0;
}

/*=====================================================================
* VERIFY : 공개키로 서명 검증 (Detached API)
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

    int result = PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig, SIG_BYTES, msg, msg_len, pk);

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

    if (strcmp(cmd, "keygen") == 0) {
        return do_keygen();
    }

    if (strcmp(cmd, "keygen_derand") == 0) {
        if (argc < 3) {
            print_error("사용 방법 : pqc_cli keygen_derand <seed_hex>");
            return 1;
        }
        return do_keygen_derand(argv[2]);
    }

    if (strcmp(cmd, "sign") == 0) {
        if (argc < 4) {
            print_error("사용 방법 : pqc_cli sign <sk_hex> <message_hex>");
            return 1;
        }
        return do_sign(argv[2], argv[3]);
    }

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