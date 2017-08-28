#include <string.h>
#include "../rng/fastrandombytes.h"
#include "poly.h"
#include "../rng/crypto_hash_sha512.h"

/* generate a random binary polynomial with degree less than N */

void
binary_poly_gen(
          uint64_t  *f,
    const uint16_t  N)
{
    uint16_t r;
    uint64_t i,j,index;
    for (i=0;i<=N/16;i++)
    {
        rng_uint16(&r);
        for (j=0;j<16;j++)
        {
            index = i*16+j;
            if (index<N)
                f[index] = (r & ( 1 << j)) >> j;
        }
    }
}


/* generate a trinary polynomial with fixed number of +/- 1s */
void
trinary_poly_gen(
          uint16_t  *f,
    const uint16_t  N,
    const uint16_t  d)
{
    uint64_t r;
    int16_t count,i, coeff[6];

    memset(f, 0, sizeof(uint16_t)*N);
    count = 0;
    while(count < d+1)
    {
        rng_uint64(&r);
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
        rng_uint64(&r);
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


/* deterministically generate a trinary polynomial with fixed number of +/- 1s
 * using seed*/
void
trinary_poly_gen_w_seed(
          uint16_t  *f,
    const uint16_t  N,
    const uint16_t  d,
    unsigned char   *seed,
    const size_t    seed_len)
{
    uint64_t r;
    int16_t count,i, coeff[6];
    int16_t j=0;
    uint64_t *seed_ptr;
    memset(f, 0, sizeof(uint16_t)*N);

    seed_ptr = (uint64_t*) seed;

    crypto_hash_sha512(seed, seed, seed_len);



    count = 0;
    while(count < d+1)
    {
        r = seed_ptr[j];
        j++;
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
        r = seed_ptr[j];
        j++;
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


void
rand_tri_poly_from_seed(
          uint16_t   *v,
    const int16_t    N,
    unsigned char    *seed,
    const size_t     seed_len)
{
  int16_t i, j, k;
  uint8_t tmp;

  i = 0;
  j = 0;

  crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);

  while (i<N)
  {
      tmp = (uint8_t)seed[j++];
      if(j==64)
      {
          crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
          j=0;
      }
      for (k=0;k<4;k++)
      {
          if ((tmp & 0b11)!=3)
          {
              v[i++] = (tmp & 0b11) - 1;
          }
          tmp >>= 2;
      }
  }
  return;
}
