#ifndef SMAUG_KEM_H
#define SMAUG_KEM_H

#include "ciphertext.h"
#include "hash.h"
#include "indcpa.h"
#include "key.h"
#include "parameters.h"
#include "randombytes.h"
#include "verify.h"

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_encap(uint8_t *ctxt, uint8_t *ss, const uint8_t *pk);
int crypto_kem_decap(uint8_t *ss, const uint8_t *sk, const uint8_t *pk,
                     const uint8_t *ctxt);


// 고정 입력 값으로 구현하기 위해서 추가 구현
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int crypto_kem_encap_derand(uint8_t *ctxt, uint8_t *ss,
                            const uint8_t *pk,
                            const uint8_t *coins);

#endif // SMAUG_KEM_H