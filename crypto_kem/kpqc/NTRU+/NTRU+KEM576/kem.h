#ifndef KEM_H
#define KEM_H

#include "params.h"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);


// 새로 추가한 함수
int crypto_kem_keypair_derand(unsigned char *pk,
                                unsigned char *sk,
                                const unsigned char *coins); // coins는 32바이트 keypair에서는


int crypto_kem_enc_derand(unsigned char *ct,
                            unsigned char *ss,
                            const unsigned char *pk,
                            const unsigned char *coins);    // 이게 문젠데, 보안레벨마다 coinst 크기가 다름
                            // NTRUPLUS_N/8 bytes 로 구성되어 있음.  현재 레벨에서는 72바이트트

#endif