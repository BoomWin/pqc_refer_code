#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "kem.h" // 추가 구현한 derand 가 존재해야함.

// api 값 참고해서 해당 구현해서는 편하게 하기 위해 상수 재정의함.
#define PK_BYTES CRYPTO_PUBLICKEYBYTES // 1728
#define SK_BYTES CRYPTO_SECRETKEYBYTES // 3488
#define CT_BYTES CRYPTO_CIPHERTEXTBYTES // 1728
#define SS_BYTES CRYPTO_BYTES   // 32

// derand용 coinst 크기 정의
#define KEYGEN_COINS_BYTES 32
#define ENCAP_COINS_BYTES (NTRUPLUS_N/8)

// ============================================================
// 유틸리티 함수
// ============================================================

// Hex → Bytes 변환
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
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

// Bytes → Hex 변환
static char* bytes_to_hex(const uint8_t *bytes, size_t len) {
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

// JSON 에러 출력
static void print_error(const char *msg) {
    printf("{\"error\":\"%s\"}\n", msg);
}


// ============================================================
// KEYGEN: 키 쌍 생성 (랜덤)
// ============================================================
static int do_keygen(void) {
    unsigned char pk[PK_BYTES];
    unsigned char sk[SK_BYTES];

    if (crypto_kem_keypair(pk, sk) != 0) {
        print_error("키 생성 실패..");
        return 1;
    }

    char *pk_hex = bytes_to_hex(pk, PK_BYTES);
    char *sk_hex = bytes_to_hex(sk, SK_BYTES);

    if (!pk_hex || !sk_hex) {
        print_error("동적 메모리 할당 실패...");
        free(pk_hex);
        free(sk_hex);
        return 1;
    }
    printf("{\"pk\":\"%s\",\"sk\":\"%s\"}\n", pk_hex, sk_hex);
    
    free(pk_hex);
    free(sk_hex);

    return 0;
}

// ============================================================
// KEYGEN_DERAND: 키 쌍 생성 (고정 시드)
// coins: 32 bytes (64 hex chars)
// ============================================================
static int do_keygen_derand(const char *coins_hex) {
    unsigned char pk[PK_BYTES];
    unsigned char sk[SK_BYTES];
    unsigned char coins[KEYGEN_COINS_BYTES];

    // Hex → Bytes
    if (hex_to_bytes(coins_hex, coins, KEYGEN_COINS_BYTES) != 0) {
        print_error("유효 하지 않은 랜덤 값 (need 64 hex chars for 32 bytes)");
        return 1;
    }

    // derand 키 생성
    // NTRU+는 역원 실패 시 -1 반환 가능!
    int ret = crypto_kem_keypair_derand(pk, sk, coins);
    if (ret != 0) {
        print_error("고정 키 생성 실패...(inverse does not exist, try different coins)");
        return 1;
    }

    char *pk_hex = bytes_to_hex(pk, PK_BYTES);
    char *sk_hex = bytes_to_hex(sk, SK_BYTES);

    if (!pk_hex || !sk_hex) {
        print_error("동적 메모리 할당 실패...");
        free(pk_hex);
        free(sk_hex);
        return 1;
    }

    printf("{\"pk\":\"%s\",\"sk\":\"%s\"}\n", pk_hex, sk_hex);

    free(pk_hex);
    free(sk_hex);
    return 0;
}


// ============================================================
// ENCAP: 캡슐화 (랜덤)
// ============================================================
static int do_encap(const char *pk_hex) {
    unsigned char pk[PK_BYTES];
    unsigned char ct[CT_BYTES];
    unsigned char ss[SS_BYTES];

    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효하지 않은 공개키 값 ...");
        return 1;
    }

    if (crypto_kem_enc(ct, ss, pk) != 0) {
        print_error("Encap 실패 ...");
        return 1;
    }

    char *ct_hex = bytes_to_hex(ct, CT_BYTES);
    char *ss_hex = bytes_to_hex(ss, SS_BYTES);

    if (!ct_hex || !ss_hex) {
        print_error("메모리 동적 할당 실패 . .. ");
        free(ct_hex);
        free(ss_hex);
        return 1;
    }

    printf("{\"ct\":\"%s\",\"ss\":\"%s\"}\n", ct_hex, ss_hex);

    free(ct_hex);
    free(ss_hex);
    return 0;
}

// ============================================================
// ENCAP_DERAND: 캡슐화 (고정 시드)
// coins: NTRUPLUS_N/8 bytes 
// ============================================================
static int do_encap_derand(const char *pk_hex, const char *coins_hex) {
    unsigned char pk[PK_BYTES];
    unsigned char ct[CT_BYTES];
    unsigned char ss[SS_BYTES];
    unsigned char coins[ENCAP_COINS_BYTES];

    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효하지 않은 공개 키 값 ... ");
        return 1;
    }

    // ★ NTRU+576: 72 bytes = 144 hex chars
    if (hex_to_bytes(coins_hex, coins, ENCAP_COINS_BYTES) != 0) {
        print_error("유효 하지 않은 고정 랜덤 값 ...  (need 144 hex chars for 72 bytes)");
        return 1;
    }

    if (crypto_kem_enc_derand(ct, ss, pk, coins) != 0) {
        print_error("Encap 실패 ... ");
        return 1;
    }

    char *ct_hex = bytes_to_hex(ct, CT_BYTES);
    char *ss_hex = bytes_to_hex(ss, SS_BYTES);

    if (!ct_hex || !ss_hex) {
        print_error("동적 할당 실패 ... ");
        free(ct_hex);
        free(ss_hex);
        return 1;
    }

    printf("{\"ct\":\"%s\",\"ss\":\"%s\"}\n", ct_hex, ss_hex);

    free(ct_hex);
    free(ss_hex);
    return 0;
}

// ============================================================
// DECAP: 역캡슐화
// ============================================================
static int do_decap(const char *sk_hex, const char *ct_hex) {
    unsigned char sk[SK_BYTES];
    unsigned char ct[CT_BYTES];
    unsigned char ss[SS_BYTES];

    if (hex_to_bytes(sk_hex, sk, SK_BYTES) != 0) {
        print_error("유효하지 않은 개인 키 ...");
        return 1;
    }

    if (hex_to_bytes(ct_hex, ct, CT_BYTES) != 0) {
        print_error("유효하지 않는 암호문 ...");
        return 1;
    }

    // ★ NTRU+ dec은 실패 시 1 반환 가능 (ML-KEM과 다름)
    if (crypto_kem_dec(ss, ct, sk) != 0) {
        print_error("Decap 실패 ...  (verification error)");
        return 1;
    }

    char *ss_hex = bytes_to_hex(ss, SS_BYTES);

    if (!ss_hex) {
        print_error("메모리 동적 할당 실패 ...");
        return 1;
    }

    printf("{\"ss\":\"%s\"}\n", ss_hex);

    free(ss_hex);
    return 0;
}

// ============================================================
// MAIN: 명령어 파싱 및 실행
// ============================================================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_error("사용 방법 : pqc_cli <keygen|keygen_derand|encap|encap_derand|decap> [args ...]");
        return 1;
    }

    const char *cmd = argv[1];

    // keygen (랜덤)
    if (strcmp(cmd, "keygen") == 0) {
        return do_keygen();
    } 

    // keygen (고정 랜덤)
    if (strcmp(cmd, "keygen_derand") == 0) {
        if (argc < 3) {
            print_error("사용 방법 : pqc_cli keygen_derand <coins_hex 값>");
            return 1;
        }
        return do_keygen_derand(argv[2]);
    }

    // encap (랜덤)
    if (strcmp(cmd, "encap") == 0) {
        if (argc < 3) {
            print_error("사용 방법 : pqc_cli encap <pk_hex>");
            return 1;
        }
        return do_encap(argv[2]);
    }

    // encap_derand(고정 시드)
    if (strcmp(cmd, "encap_derand") == 0) {
        if (argc < 4) {
            print_error("사용 방법 : pqc_cli encap_derand <pk_hex> <coins_hex 각 보안 레벨에 맞게>");
            return 1;
        }
        return do_encap_derand(argv[2], argv[3]);
    }

    // decap
    if (strcmp(cmd, "decap") == 0) {
        if (argc < 4) {
            print_error("사용 방법 : pqc_cli decap <sk_hex> <ct_hex>");
            return 1;
        }
        return do_decap(argv[2], argv[3]);
    }

    print_error("unknown command .. ");
    return 1;
}