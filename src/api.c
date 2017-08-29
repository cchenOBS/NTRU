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

#define TEST_PARAM_SET  NTRU_CCA_443



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

    /* pack F into sk */
    pack_secret_key(sk, param, F, h);



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
    uint16_t    *buf, *mem, *h, *cpoly, *mpoly;
    param   = get_param_set_by_id(pk[0]);

    *clen    =   (unsigned long long ) param->packpk;

    if (param->id==NTRU_KEM_443 || param->id == NTRU_KEM_743)
    {
        mem     = malloc(sizeof(uint16_t)*param->padN*3);
        buf     = malloc(sizeof(uint16_t)*param->padN*5);
        h       = mem;
        cpoly   = h     + param->padN;
        mpoly   = cpoly + param->padN;

        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*5);

        /* pad the message */
        if (pad_msg( mpoly, (char*) m, mlen, param) == -1)
            return -1;

        unpack_public_key( pk,param, h);

        encrypt_kem(mpoly, h, cpoly, buf, param);

        pack_public_key (c, param, cpoly);

        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*5);
        free(mem);
        free(buf);
    }
    else if (param->id==NTRU_CCA_443 || param->id == NTRU_CCA_743)
    {
        mem     = malloc(sizeof(uint16_t)*param->padN*2);
        buf     = malloc(sizeof(uint16_t)*param->padN*6);
        h       = mem;
        cpoly   = h     + param->padN;

        unpack_public_key( pk,param, h);

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
    uint16_t    *buf, *mem, *F, *cpoly, *mpoly, *h;
    param   =   get_param_set_by_id(c[0]);
    h       =   0;
    if ( param->id==NTRU_KEM_443 || param->id == NTRU_KEM_743)
    {
        mem     = malloc(sizeof(uint16_t)*param->padN*3);
        buf     = malloc(sizeof(uint16_t)*param->padN*4);
        F       = mem;
        cpoly   = F     + param->padN;
        mpoly   = cpoly + param->padN;
        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*4);

        unpack_public_key (c, param, cpoly);

        unpack_secret_key (sk, param, F, h);

        decrypt_kem(mpoly, F, cpoly, buf, param);

        *mlen = recover_msg((char*)m, mpoly, param);

        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*4);
        free(mem);
        free(buf);
    }
    else if (param->id==NTRU_CCA_443 || param->id == NTRU_CCA_743)
    {
        uint16_t    *h;
        mem     = malloc(sizeof(uint16_t)*param->padN*4);
        buf     = malloc(sizeof(uint16_t)*param->padN*7);
        F       = mem;
        cpoly   = F     + param->padN;
        mpoly   = cpoly + param->padN;
        h       = mpoly + param->padN;
        memset(mem,0, sizeof(uint16_t)*param->padN*4);
        memset(buf,0, sizeof(uint16_t)*param->padN*7);

        unpack_public_key (c, param, cpoly);

        unpack_secret_key (sk, param, F, h);

        *mlen = decrypt_cca(m,  F, h, cpoly,  buf, param);
    }
    else
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    return 0;
}

/* ebacs API: encryption with KAT */
int crypto_encrypt_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness)
{
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
    return 0;
}
