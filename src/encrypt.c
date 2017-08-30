/*
 * api.c
 *
 *  Created on: Aug 29, 2017
 *      Author: zhenfei
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "api.h"
#include "NTRUEncrypt.h"
#include "packing.h"
#include "rng/crypto_hash_sha512.h"




/* ebacs API: key gen */
int crypto_encrypt_keypair(
    unsigned char       *pk,
    unsigned char       *sk)
{
    uint16_t    *F, *g, *h, *buf, *mem;
    PARAM_SET   *param;

    param   = get_param_set_by_id(TEST_PARAM_SET);

    /* memory for 3 ring elements: f, g and h */
    mem     = malloc (sizeof(uint16_t)*param->padN * 3);
    buf     = malloc (sizeof(uint16_t)*param->padN * 6);
    if (!mem )
    {
        printf("malloc error!\n");
        return -1;
    }

    F = mem;
    g = F   + param->padN;
    h = g   + param->padN;

    keygen(F,g,h,buf,param);

    /* pack h into pk */
    pack_public_key(pk, param, h);

    /* pack F,h into sk */
    pack_secret_key_CCA(sk, param, F, h);


    free(mem);
    free(buf);

    return 0;
}

/* ebacs API: encryption */
int crypto_encrypt(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk)
{
    PARAM_SET   *param;
    uint16_t    *buf, *mem, *h, *cpoly;
    param   = get_param_set_by_id(pk[0]);

    *clen   = (unsigned long long ) param->packpk;

    if (param->id==NTRU_CCA_443 || param->id == NTRU_CCA_743)
    {
        mem     = malloc(sizeof(uint16_t)*param->padN*2);
        buf     = malloc(sizeof(uint16_t)*param->padN*6);
        h       = mem;
        cpoly   = h     + param->padN;

        unpack_public_key(pk,param, h);

        encrypt_cca(cpoly, (char*) m, mlen, h,  buf, param);

        pack_public_key (c, param, cpoly);

        memset(mem,0, sizeof(uint16_t)*param->padN*2);
        memset(buf,0, sizeof(uint16_t)*param->padN*6);
        free(mem);
        free(buf);
    }
    else
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    return 0;
}

/* ebacs API: decryption */
int crypto_encrypt_open(
    unsigned char       *m,
    unsigned long long  *mlen,
    const unsigned char *c,
    unsigned long long  clen,
    const unsigned char *sk)
{
    PARAM_SET   *param;
    param   =   get_param_set_by_id(c[0]);

    if (param->id!=NTRU_CCA_443 && param->id != NTRU_CCA_743)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    uint16_t    *buf, *mem, *F, *cpoly, *h;
    mem     = malloc(sizeof(uint16_t)*param->padN*4);
    buf     = malloc(sizeof(uint16_t)*param->padN*8);

    if(!mem || !buf)
    {
        printf("malloc error\n");
        return -1;
    }

    F       = mem;
    cpoly   = F     + param->padN;
    h       = cpoly + param->padN;

    memset(mem,0, sizeof(uint16_t)*param->padN*3);
    memset(buf,0, sizeof(uint16_t)*param->padN*8);

    unpack_public_key (c, param, cpoly);

    unpack_secret_key_CCA (sk, param, F, h);

    *mlen = decrypt_cca((char*) m,  F, h, cpoly,  buf, param);

    free(mem);
    free(buf);


    return 0;
}

/* ebacs API: encryption with KAT */
int crypto_encrypt_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness)
{

    uint16_t    *F, *g, *h, *buf, *mem;
    PARAM_SET   *param;

    param   = get_param_set_by_id(TEST_PARAM_SET);

    /* memory for 3 ring elements: f, g and h */
    mem     = malloc (sizeof(uint16_t)*param->padN * 3);
    buf     = malloc (sizeof(uint16_t)*param->padN * 6);
    if (!mem || !buf)
    {
        printf("malloc error!\n");
        return -1;
    }

    F = mem;
    g = F   + param->padN;
    h = g   + param->padN;

    printf("printing randomness string: %s\n", randomness);

    keygen_KAT(F,g,h,buf,param, randomness);

    /* pack h into pk */
    pack_public_key(pk, param, h);

    /* pack F,h into sk */
    pack_secret_key_CCA(sk, param, F, h);


    free(mem);
    free(buf);



    return 0;
}

/* ebacs API: decryption with KAT */
int crypto_encrypt_KAT(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk,
    const unsigned char *randomness)
{


    PARAM_SET   *param;

    param   = get_param_set_by_id(pk[0]);
    if (param->id!=NTRU_CCA_443 && param->id != NTRU_CCA_743)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }


    uint16_t    *buf, *mem, *h, *cpoly;
    unsigned char *seed;
    unsigned char salt[32] = "CCA_KAT:";


    *clen   = (unsigned long long ) param->packpk;
    seed    = malloc(sizeof(unsigned char)*LENGTH_OF_HASH);
    if(!seed)
    {
       printf("malloc error\n");
       return -1;
    }
    memcpy(seed, randomness, 32);
    memcpy(seed+32, salt, 32);

    printf("seed: %s\n", seed);

    mem     = malloc(sizeof(uint16_t)*param->padN*2);
    buf     = malloc(sizeof(uint16_t)*param->padN*6);
    h       = mem;
    cpoly   = h     + param->padN;

    unpack_public_key(pk,param, h);
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    encrypt_cca_KAT(cpoly, (char*) m, mlen, h,  buf, param, seed);

    pack_public_key (c, param, cpoly);

    memset(seed, 0, LENGTH_OF_HASH);
    memset(mem, 0, sizeof(uint16_t)*param->padN*2);
    memset(buf, 0, sizeof(uint16_t)*param->padN*6);
    free(seed);
    free(mem);
    free(buf);

    return 0;
}
