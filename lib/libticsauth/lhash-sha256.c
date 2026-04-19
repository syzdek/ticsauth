/*
 *  TICS Implements Complete Specifications Authenticator
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
#define __LIB_LIBTICSAUTH_LHASH_SHA256_C
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

#include "lhash-sha256.h"


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#define SHA256_ROTATE(word, bits) (((word) >> (bits)) | ((word) << (32-(bits))))


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

inline int
tics_shaxxx_process_msg_block(
         tics_hash_sha256_t *          ctx );


inline int
tics_shaxxx_result(
         tics_hash_sha256_t *          ctx,
         uint8_t *                     md,
         size_t                        md_word_len );


inline int
tics_shaxxx_update(
         tics_hash_sha256_t *          ctx,
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
         tics_hash_sha256_t *          ctx )
{
   size_t               i;
   size_t               word;
   size_t               byte;
   uint32_t             s0;
   uint32_t             s1;
   uint32_t             a;
   uint32_t             b;
   uint32_t             c;
   uint32_t             d;
   uint32_t             e;
   uint32_t             f;
   uint32_t             g;
   uint32_t             h;
   uint32_t             ch;
   uint32_t             temp1;
   uint32_t             temp2;
   uint32_t             maj;
   uint32_t             w[64];
   const uint32_t *     k = (const uint32_t [])
   {  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
   };

   assert(ctx != NULL);

   for(word = 0, byte = 0; (word < 16); word++, byte += 4)
      w[word] = (((uint32_t)ctx->msg_block[byte+0]) << 24)
              | (((uint32_t)ctx->msg_block[byte+1]) << 16)
              | (((uint32_t)ctx->msg_block[byte+2]) <<  8)
              |  ((uint32_t)ctx->msg_block[byte+3]);
   ctx->msg_block_idx = 0;

   for(i = 16; (i < 64); i++)
   {  s0 = SHA256_ROTATE(w[i-15], 7) ^ SHA256_ROTATE(w[i-15], 18) ^ (w[i-15] >> 3);
      s1 = SHA256_ROTATE(w[i-2], 17) ^ SHA256_ROTATE(w[i-2], 19) ^ (w[i-2] >> 10);
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

   for(i = 0; (i < 64); i++)
   {  s1    = SHA256_ROTATE(e, 6) ^ SHA256_ROTATE(e, 11) ^ SHA256_ROTATE(e, 25);
      ch    = (e & f) ^ ((~e) & g);
      temp1 = h + s1 + ch + k[i] + w[i];
      s0    = SHA256_ROTATE(a, 2) ^ SHA256_ROTATE(a, 13) ^ SHA256_ROTATE(a, 22);
      maj   = (a & b) ^ (a & c) ^ (b & c);
      temp2 = s0 + maj;

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
         tics_hash_sha256_t *          ctx,
         uint8_t *                     md,
         size_t                        md_word_len )
{
   uint64_t             pad_len;
   uint64_t             l;
   uint64_t             idx;
   uint64_t             byte;
   uint64_t             word;
   uint8_t              padding[128];
   tics_hash_sha256_t   res;

   assert(ctx != NULL);
   assert(md  != NULL);

   // calculate padding
   pad_len     = 64-((ctx->len + 8) % 64);
   l           = ctx->len * 8;
   padding[0]  = 0x80;
   for(idx = 1; (idx < pad_len); idx++)
      padding[idx] = 0;
   padding[pad_len++] = (l >> 56) & 0xff;
   padding[pad_len++] = (l >> 48) & 0xff;
   padding[pad_len++] = (l >> 40) & 0xff;
   padding[pad_len++] = (l >> 32) & 0xff;
   padding[pad_len++] = (l >> 24) & 0xff;
   padding[pad_len++] = (l >> 16) & 0xff;
   padding[pad_len++] = (l >>  8) & 0xff;
   padding[pad_len++] =  l        & 0xff;

   memcpy(&res, ctx, sizeof(tics_hash_sha256_t));
   for(idx = 0; (idx < pad_len); idx++)
   {  res.msg_block[res.msg_block_idx++] = padding[idx];
      if (res.msg_block_idx == 64)
         tics_shaxxx_process_msg_block(&res);
   };

   for(word = 0, byte = 0; (word < md_word_len); word++)
   {  md[byte++] = (res.h[word] >> 24) & 0xff;
      md[byte++] = (res.h[word] >> 16) & 0xff;
      md[byte++] = (res.h[word] >>  8) & 0xff;
      md[byte++] =  res.h[word]        & 0xff;
   };

   return(TICS_SUCCESS);
}


int
tics_shaxxx_update(
         tics_hash_sha256_t *          ctx,
         const void *                  data,
         size_t                        data_len )
{
   size_t      idx;

   assert(ctx      != NULL);
   assert(data     != NULL);

   // add to length of message
   if ((0x00ffffffffffffffLLU - ctx->len) < data_len)
      return(TICS_EMSG2BIG);
   ctx->len += data_len;

   // process message in 512 bit chunks
   for(idx = 0; (idx < data_len); idx++)
   {  ctx->msg_block[ctx->msg_block_idx++] = (((const uint8_t *)data)[idx] & 0xFF);
      if (ctx->msg_block_idx == 64)
         tics_shaxxx_process_msg_block(ctx);
   };

   return(TICS_SUCCESS);
}


//-------------------//
// SHA-224 functions //
//-------------------//
#pragma mark SHA-224 functions

void *
tics_sha224(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md )
{
   tics_hash_sha224_t   ctx;

   assert(data       != NULL);
   assert(md         != NULL);

   memset(&ctx, 0, sizeof(ctx));
   if ((tics_sha224_reset(&ctx)))
      return(NULL);
   if ((tics_shaxxx_update(&ctx, data, data_len)))
      return(NULL);
   if ((tics_shaxxx_result(&ctx, md, 7)))
      return(NULL);

   return(md);
}


int
tics_sha224_reset(
         tics_hash_sha224_t *          ctx )
{
   assert(ctx != NULL);

   memset(ctx, 0, sizeof(tics_hash_sha224_t));
   ctx->h[0] = 0xc1059ed8;
   ctx->h[1] = 0x367cd507;
   ctx->h[2] = 0x3070dd17;
   ctx->h[3] = 0xf70e5939;
   ctx->h[4] = 0xffc00b31;
   ctx->h[5] = 0x68581511;
   ctx->h[6] = 0x64f98fa7;
   ctx->h[7] = 0xbefa4fa4;

   return(TICS_SUCCESS);
}

int
tics_sha224_result(
         tics_hash_sha224_t *          ctx,
         uint8_t *                     md )
{
   assert(ctx != NULL);
   assert(md  != NULL);
   return(tics_shaxxx_result(ctx, md, 7));
}


int
tics_sha224_update(
         tics_hash_sha224_t *          ctx,
         const void *                  data,
         size_t                        data_len )
{
   assert(ctx      != NULL);
   assert(data     != NULL);
   return(tics_shaxxx_update(ctx, data, data_len));
}


//-------------------//
// SHA-256 functions //
//-------------------//
#pragma mark SHA-256 functions

void *
tics_sha256(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md )
{
   tics_hash_sha256_t   ctx;

   assert(data       != NULL);
   assert(md         != NULL);

   memset(&ctx, 0, sizeof(ctx));
   if ((tics_sha256_reset(&ctx)))
      return(NULL);
   if ((tics_sha256_update(&ctx, data, data_len)))
      return(NULL);
   if ((tics_sha256_result(&ctx, md)))
      return(NULL);

   return(md);
}


int
tics_sha256_reset(
         tics_hash_sha256_t *          ctx )
{
   assert(ctx != NULL);

   memset(ctx, 0, sizeof(tics_hash_sha256_t));
   ctx->h[0] = 0x6a09e667;
   ctx->h[1] = 0xbb67ae85;
   ctx->h[2] = 0x3c6ef372;
   ctx->h[3] = 0xa54ff53a;
   ctx->h[4] = 0x510e527f;
   ctx->h[5] = 0x9b05688c;
   ctx->h[6] = 0x1f83d9ab;
   ctx->h[7] = 0x5be0cd19;

   return(TICS_SUCCESS);
}


int
tics_sha256_result(
         tics_hash_sha256_t *          ctx,
         uint8_t *                     md )
{
   assert(ctx != NULL);
   assert(md  != NULL);
   return(tics_shaxxx_result(ctx, md, 8));
}


int
tics_sha256_update(
         tics_hash_sha256_t *          ctx,
         const void *                  data,
         size_t                        data_len )
{
   assert(ctx      != NULL);
   assert(data     != NULL);
   return(tics_shaxxx_update(ctx, data, data_len));
}

/* end of source */
