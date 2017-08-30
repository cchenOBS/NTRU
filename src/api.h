/*
 * api.h
 *
 *  Created on: Aug 29, 2017
 *      Author: zhenfei
 */

#ifndef API_H_
#define API_H_

#define TEST_NTRU_KEM_443




#ifdef TEST_NTRU_CCA_443
    #define TEST_PARAM_SET  NTRU_CCA_443
    #define CRYPTO_SECRETKEYBYTES 700   /* secret key length */
    #define CRYPTO_PUBLICKEYBYTES 610   /* public key length */
    #define CRYPTO_BYTES 32             /* padding ? */
    #define CRYPTO_RANDOMBYTES 32       /* random input */
#endif

#ifdef TEST_NTRU_CCA_743
    #define TEST_PARAM_SET  NTRU_CCA_743
    #define CRYPTO_SECRETKEYBYTES 1172  /* secret key length */
    #define CRYPTO_PUBLICKEYBYTES 1022  /* public key length */
    #define CRYPTO_BYTES 32             /* padding ? */
    #define CRYPTO_RANDOMBYTES 32       /* random input */
#endif

#ifdef TEST_NTRU_KEM_443
    #define TEST_PARAM_SET  NTRU_KEM_443
    #define CRYPTO_SECRETKEYBYTES 90    /* secret key length */
    #define CRYPTO_PUBLICKEYBYTES 610   /* public key length */
    #define CRYPTO_BYTES 32             /* shared secret length */
    #define CRYPTO_CIPHERTEXTBYTES 610
    #define CRYPTO_RANDOMBYTES 32       /* random input */
#endif

#ifdef TEST_NTRU_KEM_743
    #define TEST_PARAM_SET  NTRU_KEM_743
    #define CRYPTO_SECRETKEYBYTES 150   /* secret key length */
    #define CRYPTO_PUBLICKEYBYTES 1022  /* public key length */
    #define CRYPTO_BYTES 32             /* shared secret length */
    #define CRYPTO_CIPHERTEXTBYTES 1022
    #define CRYPTO_RANDOMBYTES 32       /* random input */
#endif

/* ebacs API: key gen */
int crypto_encrypt_keypair(
    unsigned char       *pk,
    unsigned char       *sk);

/* ebacs API: encryption */
int crypto_encrypt(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk);

/* ebacs API: decryption */
int crypto_encrypt_open(
    unsigned char       *m,
    unsigned long long  *mlen,
    const unsigned char *c,
    unsigned long long  clen,
    const unsigned char *sk);

/* ebacs API: encryption with KAT */
int crypto_encrypt_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness);

/* ebacs API: decryption with KAT */
int crypto_encrypt_KAT(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk,
    const unsigned char *randomness);


int crypto_kem_keygenerate(
    unsigned char       *pk,
    unsigned char       *sk);

int crypto_kem_encapsulate(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk);

int crypto_kem_decapsulate(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk);

int crypto_kem_keygenerate_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness);

int crypto_kem_encapsulate_KAT(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk,
    const unsigned char *randomness);

#endif /* API_H_ */
