/*
 * NTRUEncrypt.h
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */

#ifndef NTRUENCRYPT_H_
#define NTRUENCRYPT_H_

#include "param.h"
#include "poly/poly.h"


/*
 * memory requirement: 4 ring elements
 */
void
keygen(
          uint16_t  *f,     /* output secret key f */
          uint16_t  *g,     /* optional output secret key g */
          uint16_t  *h,     /* output public key h */
          uint16_t  *buf,
    const PARAM_SET *param);

/*
 * memory requirement: 4 ring elements
 */
int check_keys(
    const uint16_t  *f,
    const uint16_t  *g,
    const uint16_t  *h,
          uint16_t  *buf,
    const PARAM_SET *param);

/*
 * memory requirement: 5 ring elements
 */

int encrypt_kem(
    const uint16_t  *m,     /* input binary message */
    const uint16_t  *h,     /* input public key */
          uint16_t  *c,     /* output ciphertext */
          uint16_t  *buf,
    const PARAM_SET *param);

void decrypt_kem(
    uint16_t    *m,     /* output binary message */
    uint16_t    *f,     /* input secret key */
    uint16_t    *cntt,  /* input ciphertext */
    uint16_t    *buf,
    PARAM_SET   *param);


/*
 * CCA-2 secure encryption algorithm using NAEP
 * memory requirement: 6 ring elements
 */
void
encrypt_cca(
          uint16_t  *c,     /* output ciphertext */
    const char      *msg,   /* input message: a string of chars */
    const size_t    msg_len,/* input the length of the message */
    const uint16_t  *h,     /* input public key */
          uint16_t  *buf,
    const PARAM_SET *param);

/*
 * CCA-2 secure encryption algorithm using NAEP
 * return the length of the message
 * memory requirement: 7 ring elements
 */
int decrypt_cca(
          char      *msg,  /* output message: a string of chars */
    const uint16_t  *f,    /* input public key */
    const uint16_t  *h,    /* input public key */
    const uint16_t  *c,    /* input ciphertext */
          uint16_t  *buf,
    const PARAM_SET *param);
#endif /* NTRUENCRYPT_H_ */
