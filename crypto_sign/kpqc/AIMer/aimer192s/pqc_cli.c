/**                                                                                                                                                
  AIMer CLI Wrapper - Node.js 적용하기 위함                                                                                                          
                                                                                                                                                     
  사용 명령어                                                                                                                                        
      ./pqc_cli keygen                                                                                                                               
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
#define PK_BYTES CRYPTO_PUBLICKEYBYTES
#define SK_BYTES CRYPTO_SECRETKEYBYTES
#define SIG_BYTES CRYPTO_BYTES

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
* KEYGEN : 키 쌍 생성
*======================================================================*/

int do_keygen(void) {
    unsigned char pk[PK_BYTES];
    unsigned char sk[SK_BYTES];

    if (crypto_sign_keypair(pk, sk) != 0) {
        print_error("키 생성 실패 ... ");
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
* AIMer는 combined API: crypto_sign(sm, smlen, m, mlen, sk)
* sm = sig || msg 형태이며, sm 통째를 "sig"로 반환
*======================================================================*/
int do_sign(const char *sk_hex, const char *msg_hex) {
    unsigned char sk[SK_BYTES];

    if (hex_to_bytes(sk_hex, sk, SK_BYTES) != 0) {
        print_error("유효하지 않은 SK HEX 값");
        return 1;
    }

    // 메시지 변환
    size_t msg_len = strlen(msg_hex) / 2;
    unsigned char *msg = malloc(msg_len);
    if (!msg) {
        print_error("메모리 할당 실패 ...");
        return 1;
    }
    if (hex_to_bytes(msg_hex, msg, msg_len) != 0) {
        print_error("유효하지 않은 message HEX 값 ... ");
        return 1;
    }

    // sm = sig || msg (combined 형태로됨)
    unsigned long long smlen = 0;
    unsigned char *sm = malloc(SIG_BYTES + msg_len);
    if (!sm) {
        print_error("메모리 할당 실패 ...");
        free(msg);
        return 1;
    }

    if (crypto_sign(sm, &smlen, msg, msg_len, sk) != 0) {
        print_error("SIGN 실패 ... ");
        free(msg);
        free(sm);
        return 1;
    }

    // sm 통째를 sig로 반환
    char *sig_hex = bytes_to_hex(sm, smlen);

    if (!sig_hex) {
        print_error("메모리 할당 실패 ...");
        free(msg);
        free(sm);
        return 1;
    }
    printf("{\"sig\":\"%s\",\"siglen\":%llu}\n", sig_hex, smlen);

    free(sig_hex);
    free(msg);
    free(sm);
    return 0;
}

/*=====================================================================
* VERIFY : 공개키로 서명 검증
* UI에서 sig(=sm 통째), message, pk 를 받지만
* AIMer는 crypto_sign_open(m, mlen, sm, smlen, pk)로 검증
* sig 안에 이미 msg가 포함되어 있어서 내부적으로 sig(=sm)만 사용
*======================================================================*/
int do_verify(const char *pk_hex, const char *msg_hex, const char *sig_hex) {
    unsigned char pk[PK_BYTES];

    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효하지 않은 PK HEX 값");
        return 1;
    }

    // sig가 실제로는 sm(=sig||msg) 통째
    size_t smlen = strlen(sig_hex) / 2;
    unsigned char *sm = malloc(smlen);
    if (!sm) {
        print_error("메모리 할당 실패");
        return 1;
    }
    if (hex_to_bytes(sig_hex, sm, smlen) != 0) {
        print_error("유효하지 않은 signature HEX 값");
        free(sm);
        return 1;
    }

    // 검증용 메시지 버퍼
    unsigned char *out_msg = malloc(smlen);
    unsigned long long out_mlen = 0;
    if (!out_msg) {
        print_error("메모리 할당 실패");
        free(sm);
        return 1;
    }

    int result = crypto_sign_open(out_msg, &out_mlen, sm, smlen, pk);

    printf("{\"valid\":%s}\n", result == 0 ? "true" : "false");

    free(sm);
    free(out_msg);
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