/*
 * kem.c
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

/* kem and encryption use a same key gen */
int crypto_kem_keygenerate(
    unsigned char *pk,
    unsigned char *sk)
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
    pack_secret_key_KEM(sk, param, F);


    free(mem);
    free(buf);

    return 0;
}


int crypto_kem_encapsulate(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk)
{

    PARAM_SET   *param;
    uint16_t    *buf, *mem, *h, *cpoly, *mpoly;
    param   = get_param_set_by_id(pk[0]);

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
        if (pad_msg( mpoly, (char*) ss, CRYPTO_BYTES, param) == -1)
            return -1;

        unpack_public_key( pk,param, h);

        encrypt_kem(mpoly, h, cpoly, buf, param);

        pack_public_key (ct, param, cpoly);

        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*5);
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


int crypto_kem_decapsulate(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk)
{
    PARAM_SET   *param;
    uint16_t    *buf, *mem, *F, *cpoly, *mpoly;
    param   =   get_param_set_by_id(ct[0]);
    if ( param->id==NTRU_KEM_443 || param->id == NTRU_KEM_743)
    {
        mem     = malloc(sizeof(uint16_t)*param->padN*3);
        buf     = malloc(sizeof(uint16_t)*param->padN*4);
        F       = mem;
        cpoly   = F     + param->padN;
        mpoly   = cpoly + param->padN;
        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*4);

        unpack_public_key (ct, param, cpoly);

        unpack_secret_key_KEM (sk, param, F);

        decrypt_kem(mpoly, F, cpoly, buf, param);

        recover_msg((char*)ss, mpoly, param);

        memset(mem,0, sizeof(uint16_t)*param->padN*3);
        memset(buf,0, sizeof(uint16_t)*param->padN*4);
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
/* todo: KAT */
