/*
 *  TICS Authenticator
 *  Copyright (C) 2026 David M. Syzdek <david@syzdek.net>.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *     3. Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#define __LIB_LIBTICSAUTH_LHASH_SHA512_C
#include "libticsauth.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "lhash-sha512.h"


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#define SHA512_ROTATE(word, bits) (((word) >> (bits)) | ((word) << (64-(bits))))


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

static int
tics_shaxxx_process_msg_block(
         tics_hash_sha512_t *          ctx );


static int
tics_shaxxx_result(
         tics_hash_sha512_t *          ctx,
         uint8_t *                     md,
         size_t                        md_word_len );


static int
tics_shaxxx_update(
         tics_hash_sha512_t *          ctx,
         const void *                  data,
         size_t                        data_len );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

//------------------//
// common functions //
//------------------//
#pragma mark common functions

int
tics_shaxxx_process_msg_block(
         tics_hash_sha512_t *          ctx )
{
   size_t               i;
   size_t               word;
   size_t               byte;
   uint64_t             s0;
   uint64_t             s1;
   uint64_t             S0;
   uint64_t             S1;
   uint64_t             a;
   uint64_t             b;
   uint64_t             c;
   uint64_t             d;
   uint64_t             e;
   uint64_t             f;
   uint64_t             g;
   uint64_t             h;
   uint64_t             ch;
   uint64_t             temp1;
   uint64_t             temp2;
   uint64_t             maj;
   uint64_t             w[80];
   const uint64_t *     k = (const uint64_t [])
   {  0x428a2f98d728ae22LLU, 0x7137449123ef65cdLLU, 0xb5c0fbcfec4d3b2fLLU,
      0xe9b5dba58189dbbcLLU, 0x3956c25bf348b538LLU, 0x59f111f1b605d019LLU,
      0x923f82a4af194f9bLLU, 0xab1c5ed5da6d8118LLU, 0xd807aa98a3030242LLU,
      0x12835b0145706fbeLLU, 0x243185be4ee4b28cLLU, 0x550c7dc3d5ffb4e2LLU,
      0x72be5d74f27b896fLLU, 0x80deb1fe3b1696b1LLU, 0x9bdc06a725c71235LLU,
      0xc19bf174cf692694LLU, 0xe49b69c19ef14ad2LLU, 0xefbe4786384f25e3LLU,
      0x0fc19dc68b8cd5b5LLU, 0x240ca1cc77ac9c65LLU, 0x2de92c6f592b0275LLU,
      0x4a7484aa6ea6e483LLU, 0x5cb0a9dcbd41fbd4LLU, 0x76f988da831153b5LLU,
      0x983e5152ee66dfabLLU, 0xa831c66d2db43210LLU, 0xb00327c898fb213fLLU,
      0xbf597fc7beef0ee4LLU, 0xc6e00bf33da88fc2LLU, 0xd5a79147930aa725LLU,
      0x06ca6351e003826fLLU, 0x142929670a0e6e70LLU, 0x27b70a8546d22ffcLLU,
      0x2e1b21385c26c926LLU, 0x4d2c6dfc5ac42aedLLU, 0x53380d139d95b3dfLLU,
      0x650a73548baf63deLLU, 0x766a0abb3c77b2a8LLU, 0x81c2c92e47edaee6LLU,
      0x92722c851482353bLLU, 0xa2bfe8a14cf10364LLU, 0xa81a664bbc423001LLU,
      0xc24b8b70d0f89791LLU, 0xc76c51a30654be30LLU, 0xd192e819d6ef5218LLU,
      0xd69906245565a910LLU, 0xf40e35855771202aLLU, 0x106aa07032bbd1b8LLU,
      0x19a4c116b8d2d0c8LLU, 0x1e376c085141ab53LLU, 0x2748774cdf8eeb99LLU,
      0x34b0bcb5e19b48a8LLU, 0x391c0cb3c5c95a63LLU, 0x4ed8aa4ae3418acbLLU,
      0x5b9cca4f7763e373LLU, 0x682e6ff3d6b2b8a3LLU, 0x748f82ee5defb2fcLLU,
      0x78a5636f43172f60LLU, 0x84c87814a1f0ab72LLU, 0x8cc702081a6439ecLLU,
      0x90befffa23631e28LLU, 0xa4506cebde82bde9LLU, 0xbef9a3f7b2c67915LLU,
      0xc67178f2e372532bLLU, 0xca273eceea26619cLLU, 0xd186b8c721c0c207LLU,
      0xeada7dd6cde0eb1eLLU, 0xf57d4f7fee6ed178LLU, 0x06f067aa72176fbaLLU,
      0x0a637dc5a2c898a6LLU, 0x113f9804bef90daeLLU, 0x1b710b35131c471bLLU,
      0x28db77f523047d84LLU, 0x32caab7b40c72493LLU, 0x3c9ebe0a15c9bebcLLU,
      0x431d67c49c100d4cLLU, 0x4cc5d4becb3e42b6LLU, 0x597f299cfc657e2aLLU,
      0x5fcb6fab3ad6faecLLU, 0x6c44198c4a475817LLU
   };

   assert(ctx != NULL);

   for(word = 0, byte = 0; (word < 16); word++, byte += 8)
      w[word] = (((uint64_t)ctx->msg_block[byte+0]) << 56)
              | (((uint64_t)ctx->msg_block[byte+1]) << 48)
              | (((uint64_t)ctx->msg_block[byte+2]) << 40)
              | (((uint64_t)ctx->msg_block[byte+3]) << 32)
              | (((uint64_t)ctx->msg_block[byte+4]) << 24)
              | (((uint64_t)ctx->msg_block[byte+5]) << 16)
              | (((uint64_t)ctx->msg_block[byte+6]) <<  8)
              |  ((uint64_t)ctx->msg_block[byte+7]);
   ctx->msg_block_idx = 0;

   for(i = 16; (i < 80); i++)
   {  s0   = SHA512_ROTATE(w[i-15], 1) ^ SHA512_ROTATE(w[i-15], 8) ^ (w[i-15] >> 7);
      s1   = SHA512_ROTATE(w[i-2], 19) ^ SHA512_ROTATE(w[i-2], 61) ^ (w[i-2] >> 6);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
   };

   a = ctx->h[0];
   b = ctx->h[1];
   c = ctx->h[2];
   d = ctx->h[3];
   e = ctx->h[4];
   f = ctx->h[5];
   g = ctx->h[6];
   h = ctx->h[7];

   for(i = 0; (i < 80); i++)
   {  S1    = SHA512_ROTATE(e, 14) ^ SHA512_ROTATE(e, 18) ^ SHA512_ROTATE(e, 41);
      ch    = (e & f) ^ ((~e) & g);
      temp1 = h + S1 + ch + k[i] + w[i];
      S0    = SHA512_ROTATE(a, 28) ^ SHA512_ROTATE(a, 34) ^ SHA512_ROTATE(a, 39);
      maj   = (a & b) ^ (a & c) ^ (b & c);
      temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
   };

   ctx->h[0] += a;
   ctx->h[1] += b;
   ctx->h[2] += c;
   ctx->h[3] += d;
   ctx->h[4] += e;
   ctx->h[5] += f;
   ctx->h[6] += g;
   ctx->h[7] += h;

   return(TICS_SUCCESS);
}


int
tics_shaxxx_result(
         tics_hash_sha512_t *          ctx,
         uint8_t *                     md,
         size_t                        md_word_len )
{
   uint64_t             pad_len;
   uint64_t             low;
   uint64_t             high;
   uint64_t             idx;
   uint64_t             byte;
   uint64_t             word;
   uint8_t              padding[256];
   tics_hash_sha512_t   res;

   assert(ctx != NULL);
   assert(md  != NULL);

   // calculate padding
   pad_len     = 128-((ctx->len_low + 16) % 128);
   low         = ctx->len_low  * 8;
   high        = ctx->len_high * 8;
   padding[0]  = 0x80;
   for(idx = 1; (idx < pad_len); idx++)
      padding[idx] = 0;
   padding[pad_len++] = (high >> 56) & 0xff;
   padding[pad_len++] = (high >> 48) & 0xff;
   padding[pad_len++] = (high >> 40) & 0xff;
   padding[pad_len++] = (high >> 32) & 0xff;
   padding[pad_len++] = (high >> 24) & 0xff;
   padding[pad_len++] = (high >> 16) & 0xff;
   padding[pad_len++] = (high >>  8) & 0xff;
   padding[pad_len++] =  high        & 0xff;
   padding[pad_len++] = (low  >> 56) & 0xff;
   padding[pad_len++] = (low  >> 48) & 0xff;
   padding[pad_len++] = (low  >> 40) & 0xff;
   padding[pad_len++] = (low  >> 32) & 0xff;
   padding[pad_len++] = (low  >> 24) & 0xff;
   padding[pad_len++] = (low  >> 16) & 0xff;
   padding[pad_len++] = (low  >>  8) & 0xff;
   padding[pad_len++] =  low         & 0xff;

   memcpy(&res, ctx, sizeof(tics_hash_sha512_t));
   for(idx = 0; (idx < pad_len); idx++)
   {  res.msg_block[res.msg_block_idx++] = padding[idx];
      if (res.msg_block_idx == 128)
         tics_shaxxx_process_msg_block(&res);
   };

   for(word = 0, byte = 0; (word < md_word_len); word++)
   {  md[byte++] = (res.h[word] >> 56) & 0xff;
      md[byte++] = (res.h[word] >> 48) & 0xff;
      md[byte++] = (res.h[word] >> 40) & 0xff;
      md[byte++] = (res.h[word] >> 32) & 0xff;
      md[byte++] = (res.h[word] >> 24) & 0xff;
      md[byte++] = (res.h[word] >> 16) & 0xff;
      md[byte++] = (res.h[word] >>  8) & 0xff;
      md[byte++] =  res.h[word]        & 0xff;
   };

   memset(padding, 0, sizeof(padding));
   memset(&res,    0, sizeof(tics_hash_sha512_t));

   return(TICS_SUCCESS);
}


int
tics_shaxxx_update(
         tics_hash_sha512_t *          ctx,
         const void *                  data,
         size_t                        data_len )
{
   size_t      idx;
   uint64_t    high;
   uint64_t    low;

   assert(ctx      != NULL);
   assert(data     != NULL);

   // add to length of message
   low   = ((uint64_t)data_len) & 0x0fffffffffffffffLLU;
   low  += ctx->len_low;
   high  = ((uint64_t)data_len) >> 61;
   high += low >> 61;
   high += ctx->len_high;
   low  &= 0x1fffffffffffffffLU;
   if ((high+ctx->len_high) < ctx->len_high)
      return(TICS_EMSG2BIG);
   ctx->len_high = high;
   ctx->len_low  = low & 0x1fffffffffffffffLU;

   // process message in 1024 bit chunks
   for(idx = 0; (idx < data_len); idx++)
   {  ctx->msg_block[ctx->msg_block_idx++] = (((const uint8_t *)data)[idx] & 0xFF);
      if (ctx->msg_block_idx == 128)
         tics_shaxxx_process_msg_block(ctx);
   };

   return(TICS_SUCCESS);
}


//-------------------//
// SHA-384 functions //
//-------------------//
#pragma mark SHA-384 functions

int
tics_sha384_reset(
         tics_hash_sha384_t *          ctx )
{
   assert(ctx != NULL);

   memset(ctx, 0, sizeof(tics_hash_sha384_t));
   ctx->h[0] = 0xcbbb9d5dc1059ed8LLU;
   ctx->h[1] = 0x629a292a367cd507LLU;
   ctx->h[2] = 0x9159015a3070dd17LLU;
   ctx->h[3] = 0x152fecd8f70e5939LLU;
   ctx->h[4] = 0x67332667ffc00b31LLU;
   ctx->h[5] = 0x8eb44a8768581511LLU;
   ctx->h[6] = 0xdb0c2e0d64f98fa7LLU;
   ctx->h[7] = 0x47b5481dbefa4fa4LLU;

   return(TICS_SUCCESS);
}

int
tics_sha384_result(
         tics_hash_sha384_t *          ctx,
         uint8_t *                     md )
{
   assert(ctx != NULL);
   assert(md  != NULL);
   return(tics_shaxxx_result(ctx, md, 6));
}


int
tics_sha384_update(
         tics_hash_sha384_t *          ctx,
         const void *                  data,
         size_t                        data_len )
{
   assert(ctx      != NULL);
   assert(data     != NULL);
   return(tics_shaxxx_update(ctx, data, data_len));
}


//-------------------//
// SHA-512 functions //
//-------------------//
#pragma mark SHA-512 functions

void *
tics_sha512(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len )
{
   tics_hash_sha512_t   ctx;

   assert(data       != NULL);
   assert(md         != NULL);

   if (md_len < TICS_MD_SIZE_SHA512)
      return(NULL);

   memset(&ctx, 0, sizeof(ctx));
   if ((tics_sha512_reset(&ctx)))
      return(NULL);
   if ((tics_sha512_update(&ctx, data, data_len)))
      return(NULL);
   if ((tics_sha512_result(&ctx, md)))
      return(NULL);

   return(md);
}


int
tics_sha512_reset(
         tics_hash_sha512_t *          ctx )
{
   assert(ctx != NULL);

   memset(ctx, 0, sizeof(tics_hash_sha512_t));
   ctx->h[0] = 0x6a09e667f3bcc908LLU;
   ctx->h[1] = 0xbb67ae8584caa73bLLU;
   ctx->h[2] = 0x3c6ef372fe94f82bLLU;
   ctx->h[3] = 0xa54ff53a5f1d36f1LLU;
   ctx->h[4] = 0x510e527fade682d1LLU;
   ctx->h[5] = 0x9b05688c2b3e6c1fLLU;
   ctx->h[6] = 0x1f83d9abfb41bd6bLLU;
   ctx->h[7] = 0x5be0cd19137e2179LLU;

   return(TICS_SUCCESS);
}


int
tics_sha512_result(
         tics_hash_sha512_t *          ctx,
         uint8_t *                     md )
{
   assert(ctx != NULL);
   assert(md  != NULL);
   return(tics_shaxxx_result(ctx, md, 8));
}


int
tics_sha512_update(
         tics_hash_sha512_t *          ctx,
         const void *                  data,
         size_t                        data_len )
{
   assert(ctx      != NULL);
   assert(data     != NULL);
   return(tics_shaxxx_update(ctx, data, data_len));
}

/* end of source */
