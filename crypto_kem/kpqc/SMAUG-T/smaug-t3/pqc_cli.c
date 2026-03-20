/**
 * SMAUG-T1 CLI Wrapper - Node.js 연동용
 *
 * 사용 명령어:
 *     ./pqc_cli keygen
 *     ./pqc_cli keygen_derand <coins_hex>        (32 bytes = 64 hex)
 *     ./pqc_cli encap <pk_hex>
 *     ./pqc_cli encap_derand <pk_hex> <coins_hex> (32 bytes = 64 hex)
 *     ./pqc_cli decap <sk_hex> <pk_hex> <ct_hex>  ★ pk도 필요!
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kem.h"

/*============================================================
    상수 정의 - api.h에서 가져옴 (SMAUG_NAMESPACE 매크로로 연결)
============================================================*/
#define PK_BYTES PUBLICKEY_BYTES
#define SK_BYTES KEM_SECRETKEY_BYTES
#define CT_BYTES CIPHERTEXT_BYTES
#define SS_BYTES CRYPTO_BYTES

#define KEYGEN_COINS_BYTES T_BYTES  // 32
#define ENCAP_COINS_BYTES DELTA_BYTES // 32


// ============================================================
// 유틸리티 함수
// ============================================================
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2)
        return -1;
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1)
            return -1;
        bytes[i] = (uint8_t)byte;
    }
    return 0;
}

static char* bytes_to_hex(const uint8_t *bytes, size_t len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

static void print_error(const char *msg) {
    printf("{\"error\":\"%s\"}\n", msg);
}

// ============================================================
// KEYGEN
// ============================================================
static int do_keygen(void) {
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];

    if (crypto_kem_keypair(pk, sk) != 0) {
        print_error("키 생성 실패");
        return 1;
    }

    char *pk_hex = bytes_to_hex(pk, PK_BYTES);
    char *sk_hex = bytes_to_hex(sk, SK_BYTES);
    if (!pk_hex || !sk_hex) {
        print_error("동적 할당 실패 ...");
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
// KEYGEN DERAND (coins: 32 bytes)
// ============================================================
static int do_keygen_derand(const char *coins_hex) {
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];
    uint8_t coins[KEYGEN_COINS_BYTES];

    if (hex_to_bytes(coins_hex, coins, KEYGEN_COINS_BYTES) != 0) {
        print_error("유효하지 않은 랜덤 hex 값 ... (need 64 hex chars)");
        return 1;
    }

    if (crypto_kem_keypair_derand(pk, sk, coins) != 0) {
        print_error("고정 Keygen 실패 ...");
        return 1;
    }

    char *pk_hex = bytes_to_hex(pk, PK_BYTES);
    char *sk_hex = bytes_to_hex(sk, SK_BYTES);
    if (!pk_hex || !sk_hex) {
        print_error("동적 할당 실패 ... "); 
        free(pk_hex); 
        free(sk_hex); 
        return 1; 
    }

    printf("{\"pk\":\"%s\",\"sk\":\"%s\"}\n", pk_hex, sk_hex);
    free(pk_hex); free(sk_hex);
    return 0;
}

// ============================================================
// ENCAP
// ============================================================
static int do_encap(const char *pk_hex) {
    uint8_t pk[PK_BYTES];
    uint8_t ct[CT_BYTES];
    uint8_t ss[SS_BYTES];

    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효 하지 않는 pk_hex 값 ... ");
        return 1;
    }

    if (crypto_kem_encap(ct, ss, pk) != 0) {
        print_error("Encap 실패 ...");
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
// ENCAP DERAND (coins: 32 bytes)
// ============================================================
  static int do_encap_derand(const char *pk_hex, const char *coins_hex) {
    uint8_t pk[PK_BYTES];
    uint8_t ct[CT_BYTES];
    uint8_t ss[SS_BYTES];
    uint8_t coins[ENCAP_COINS_BYTES];

    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효 하지 않은 pk_hex 값 ... ");
        return 1;
    }
    if (hex_to_bytes(coins_hex, coins, ENCAP_COINS_BYTES) != 0) {
        print_error("유효하지 않은 고정 랜덤 값 ...  (need 64 hex chars)");
        return 1;
    }

    if (crypto_kem_encap_derand(ct, ss, pk, coins) != 0) {
        print_error("랜덤 고정 Encap 실패 ...");
        return 1;
    }

    char *ct_hex = bytes_to_hex(ct, CT_BYTES);
    char *ss_hex = bytes_to_hex(ss, SS_BYTES);
    if (!ct_hex || !ss_hex) {
        print_error("동적 할당 실패 ..."); 
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
// DECAP : pk도 필요!
// ============================================================
static int do_decap(const char *sk_hex, const char *pk_hex, const char *ct_hex) {
    uint8_t sk[SK_BYTES];
    uint8_t pk[PK_BYTES];
    uint8_t ct[CT_BYTES];
    uint8_t ss[SS_BYTES];

    if (hex_to_bytes(sk_hex, sk, SK_BYTES) != 0) {
        print_error("유효 하지 않는 sk 값 ... ");
        return 1;
    }
    if (hex_to_bytes(pk_hex, pk, PK_BYTES) != 0) {
        print_error("유효 하지 않는 pk 값 ... ");
        return 1;
    }
    if (hex_to_bytes(ct_hex, ct, CT_BYTES) != 0) {
        print_error("유효 하지 않는 ct 값 ... ");
        return 1;
    }

    // decap 수행 시 에  pk도 필요함 (이거 나중에 route 매핑할때 추가 해야 할듯 ?)
    if (crypto_kem_decap(ss, sk, pk, ct) != 0) {
        print_error("Decap 실패 ... ");
        return 1;
    }

    char *ss_hex = bytes_to_hex(ss, SS_BYTES);
    if (!ss_hex) { 
        print_error("동적 할당 실패 ..."); 
        return 1; 
    }

    printf("{\"ss\":\"%s\"}\n", ss_hex);
    free(ss_hex);
    return 0;
}


// ============================================================
// MAIN
// ============================================================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_error("사용 방법 : pqc_cli <keygen|keygen_derand|encap|encap_derand|decap> [args...]");
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "keygen") == 0) {
        return do_keygen();
    }

    if (strcmp(cmd, "keygen_derand") == 0) {
        if (argc < 3) {
            print_error("사용 방법 : pqc_cli keygen_derand <coins_hex>");
            return 1;
        }
        return do_keygen_derand(argv[2]);
    }

    if (strcmp(cmd, "encap") == 0) {
        if (argc < 3) {
            print_error("사용 방법 : pqc_cli encap <pk_hex>");
            return 1;
        }
        return do_encap(argv[2]);
    }

    if (strcmp(cmd, "encap_derand") == 0) {
        if (argc < 4) { 
            print_error("사용 방법 : pqc_cli encap_derand <pk_hex> <coins_hex>"); 
            return 1; 
        }
        return do_encap_derand(argv[2], argv[3]);
    }

    if (strcmp(cmd, "decap") == 0) {
        if (argc < 5) {
            print_error("사용 방법 : pqc_cli decap <sk_hex> <pk_hex> <ct_hex>");
            return 1;
        }
        return do_decap(argv[2], argv[3], argv[4]);
    }
    print_error("unknown command");
    return 1;
}