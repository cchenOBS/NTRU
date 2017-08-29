/*
 * api.h
 *
 *  Created on: Aug 29, 2017
 *      Author: zhenfei
 */

#ifndef API_H_
#define API_H_

#define CRYPTO_SECRETKEYBYTES 256   /* secret key length */
#define CRYPTO_PUBLICKEYBYTES 85    /* public key length */
#define CRYPTO_BYTES 32             /* padding ? */
#define CRYPTO_RANDOMBYTES 32       /* random input */

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

#endif /* API_H_ */
