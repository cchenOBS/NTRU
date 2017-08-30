/*
 * KAT.c
 *
 *  Created on: Aug 30, 2017
 *      Author: zhenfei
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "param.h"
#include "rng/crypto_hash_sha512.h"
#include "poly/poly.h"



/* generate a trinary polynomial with fixed number of +/- 1s */
void
trinary_poly_gen_KAT(
          uint16_t  *f,
    const uint16_t  N,
    const uint16_t  d,
    unsigned char   *seed)
{
    uint64_t r, *tmp;
    int16_t count,i,j, coeff[6];

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    tmp = (uint64_t *)seed;

    memset(f, 0, sizeof(uint16_t)*N);
    count = 0;
    j = 0;
    while(count < d+1)
    {
        r  = tmp[j++];
        if(j==8)
        {
            crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
            j = 0;
        }

        for (i =0;i<6;i++)
        {
            coeff[i] = r & 0x3FF;
            r = (r - coeff[i])>>10;
            if (coeff[i]<N)
            {
                if (f[coeff[i]]==0)
                {
                    f[coeff[i]]=1;
                    count++;
                }
            }
        }
    }
    count = 0;
    while(count < d)
    {
        r  = tmp[j++];
        if(j==8)
        {
            crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
            j = 0;
        }
        for (i =0;i<6;i++)
        {
            coeff[i] = r & 0x3FF;
            r = (r - coeff[i])>>10;
            if (coeff[i]<N)
            {
                if (f[coeff[i]]==0)
                {
                    f[coeff[i]]=-1;
                    count++;
                }
            }
        }
    }
    return;
}


/*
 * memory requirement: 6 ring elements
 */
void
keygen_KAT(
          uint16_t  *F,     /* output secret key f */
          uint16_t  *g,     /* optional output secret key g */
          uint16_t  *h,     /* output public key h */
          uint16_t  *buf,
    const PARAM_SET *param,
    const unsigned char *randomness)
{
    int16_t     i;
    uint16_t    *f;
    uint16_t    *f_inv;
    uint16_t    *localbuf;
    unsigned char *seed;
    unsigned char salt[32] = "keygen_KAT|keygen_KAT|keygen_KAT";

    f           = buf;
    f_inv       = f     + param->padN;
    /* three ring elements for karatsuba */
    localbuf    = f_inv + param->padN;
    seed        = (unsigned char*) malloc(sizeof(unsigned char)*LENGTH_OF_HASH);
    if(!seed)
    {
        printf("malloc error\n");
        return;
    }
    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    do{
        /* generate f = pF+1 until f is invertible mod 2*/
        trinary_poly_gen_KAT(F, param->N, param->d, seed);
        crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
        for (i=0;i<param->N;i++)
            f[i] = param->p*F[i];
        f[0]++;
    }while (ntru_ring_inv(f, param->N, localbuf, f_inv) == -1);

    /* compute f^-1 by lifting f_inv mod 2 to f_inv mod q*/
    ring_lift_inv_pow2(f_inv, f, param, localbuf);

    /* generate g*/
    trinary_poly_gen_KAT(g, param->N, param->d, seed);

    for (i=0;i<param->N;i++)
    {
        f[i] = f[i] & 0x7FF;
        g[i] = g[i] & 0x7FF;
    }

    /* compute h = f^-1*g */
    ntru_ring_mult_coefficients(f_inv, g, param, localbuf, h);

    memset(seed, 0, sizeof(unsigned char)*LENGTH_OF_HASH);
    memset(buf,  0, sizeof(uint16_t)*param->padN*6);
    free(seed);
    return;
}



/*
 * check if a message length is valid for ntruencrypt-cca
 * then convert the message into a binary polynomial and
 * pad the message with a random binary string p
 */
int
pad_msg_KAT(
          uint16_t  *m,     /* output message */
    const char      *msg,   /* input message string */
    const size_t    msg_len,/* input length of the message */
    const PARAM_SET *param,
    unsigned char   *seed)
{
    if (msg_len > param->max_msg_len)
    {
        printf("error: message too long");
        return -1;
    }
    uint16_t    *pad;
    uint16_t    i,j;
    char        tmp;
    memset(m, 0, sizeof(uint16_t)*param->N);

    /* generate the pad of a degree 167 trinary polynomial*/
    pad = m + param->N - 167;
    trinary_poly_gen_KAT(pad, 167, 56, seed);

    /* form the message binary polynomial */
    for (i=0;i<msg_len;i++)
    {
        tmp = msg[i];
        for(j=0;j<8;j++)
        {
            m[i*8+j] = tmp & 1;
            tmp >>= 1;
        }
    }
    return 0;
}


/*
 * CCA-2 secure encryption algorithm using NAEP
 * memory requirement: 6 ring elements
 */
void
encrypt_cca_KAT(
          uint16_t  *c,     /* output ciphertext */
    const char      *msg,   /* input message: a string of chars */
    const size_t    msg_len,/* input the length of the message */
    const uint16_t  *h,     /* input public key */
          uint16_t  *buf,
    const PARAM_SET *param,
    unsigned char   *seed)
{
    uint16_t    i;
    uint16_t    *r, *t, *m, *localbuf;

    m           = buf;
    r           = buf   + param->padN;
    t           = r     + param->padN;
    localbuf    = t     + param->padN;

    /* pad the message */
    if (pad_msg_KAT( m, msg, msg_len, param,seed) == -1)
        return;

    /* generate r from the message */
    if (generate_r(r, m, h, localbuf, param) == -1)
        return;

    /* compute r*h */
    ntru_ring_mult_coefficients(r, h, param, localbuf, t);
    for (i=0;i<param->N;i++)
    {
        t[i] *= param->p;
        t[i] &= (param->q-1);
    }

    /* mask the message with hash(r*h) */
    mask_m (m, t, localbuf, param);


    for (i=0;i<param->N;i++)
        c[i] = (t[i] + m[i]) & (param->q-1);

    memset(buf,0, sizeof(uint16_t)*param->padN*6);

    return ;
}


/*
 * memory requirement: 5 ring elements
 */

int encrypt_kem_KAT(
    const uint16_t  *m,     /* input binary message */
    const uint16_t  *h,     /* input public key */
          uint16_t  *c,     /* output ciphertext */
          uint16_t  *buf,
    const PARAM_SET *param,
    unsigned char   *seed)
{
    if (check_m(m, param->N) == -1 )
    {
        printf("error message\n");
        return -1;
    }
    uint16_t    i;
    uint16_t    *r, *t, *localbuf;


    r           = buf;
    t           = r + param->padN;
    /* three ring elements for karatsuba */
    localbuf    = t + param->padN;

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    trinary_poly_gen_KAT(r, param->N, param->d, seed);

    ntru_ring_mult_coefficients(r, h, param, localbuf, t);

    for (i=0;i<param->N;i++)
        c[i] = (t[i]*param->p + m[i]) & (param->q-1);

    memset(buf, 0, sizeof(uint16_t)*param->padN*5);
    return 0;
}
