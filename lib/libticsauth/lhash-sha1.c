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
#define __LIB_LIBTICSAUTH_LHASH_SHA1_C
#include "libticsauth.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <string.h>
#include <assert.h>

#include "lhash-sha1.h"


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#define SHA1_SHIFT(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#define TICS_HASH_SHA1_SIZE         20


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

static void
tics_sha1_pad_msg(
         tics_hash_sha1_t *            ctx );


static void
tics_sha1_process_msg_block(
         tics_hash_sha1_t *            ctx );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

void *
tics_sha1(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len )
{
   tics_hash_sha1_t  ctx;

   assert(data       != NULL);
   assert(md         != NULL);

   if (md_len < TICS_MD_SIZE_SHA1)
      return(NULL);

   memset(&ctx, 0, sizeof(ctx));

   if ((tics_sha1_reset(&ctx)))
      return(NULL);

   if ((tics_sha1_update(&ctx, data, data_len)))
      return(NULL);

   if ((tics_sha1_result(&ctx, md)))
      return(NULL);

   return(md);
}


void
tics_sha1_pad_msg(
         tics_hash_sha1_t *            ctx )
{
   if (ctx->msg_block_idx > 55)
   {  ctx->msg_block[ctx->msg_block_idx++] = 0x80;
      while(ctx->msg_block_idx < 64)
         ctx->msg_block[ctx->msg_block_idx++] = 0;
      tics_sha1_process_msg_block(ctx);
      while(ctx->msg_block_idx < 56)
         ctx->msg_block[ctx->msg_block_idx++] = 0;
   } else
   {  ctx->msg_block[ctx->msg_block_idx++] = 0x80;
      while(ctx->msg_block_idx < 56)
         ctx->msg_block[ctx->msg_block_idx++] = 0;
   };

   // Store the message length as the last 8 octets
   ctx->msg_block[56] = (ctx->len >> 56) & 0xff;
   ctx->msg_block[57] = (ctx->len >> 48) & 0xff;
   ctx->msg_block[58] = (ctx->len >> 40) & 0xff;
   ctx->msg_block[59] = (ctx->len >> 32) & 0xff;
   ctx->msg_block[60] = (ctx->len >> 24) & 0xff;
   ctx->msg_block[61] = (ctx->len >> 16) & 0xff;
   ctx->msg_block[62] = (ctx->len >>  8) & 0xff;
   ctx->msg_block[63] = (ctx->len >>  0) & 0xff;
   tics_sha1_process_msg_block(ctx);

   return;
}


void
tics_sha1_process_msg_block(
         tics_hash_sha1_t *            ctx )
{
   unsigned       t;       // Loop counter
   uint32_t       temp;    // temporary word value
   uint32_t       w[80];   // Word sequence
   uint32_t       a;       // word buffers
   uint32_t       b;       // word buffers
   uint32_t       c;       // word buffers
   uint32_t       d;       // word buffers
   uint32_t       e;       // word buffers

   const uint32_t k[] =    // SHA-1 constants
   {  0x5A827999,
      0x6ED9EBA1,
      0x8F1BBCDC,
      0xCA62C1D6
   };

   for(t = 0; (t < 16); t++)
   {  w[t]  = ctx->msg_block[t * 4 + 0] << 24;
      w[t] |= ctx->msg_block[t * 4 + 1] << 16;
      w[t] |= ctx->msg_block[t * 4 + 2] <<  8;
      w[t] |= ctx->msg_block[t * 4 + 3];
   };

   for(t = 16; (t < 80); t++)
      w[t] = SHA1_SHIFT(1, (w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]));

   a = ctx->msg_digest[0];
   b = ctx->msg_digest[1];
   c = ctx->msg_digest[2];
   d = ctx->msg_digest[3];
   e = ctx->msg_digest[4];

   for(t = 0; t < 20; t++)
   {  temp =  SHA1_SHIFT(5, a) + ((b & c) | ((~b) & d)) + e + w[t] + k[0];
      e = d;
      d = c;
      c = SHA1_SHIFT(30,b);
      b = a;
      a = temp;
   };

   for(t = 20; t < 40; t++)
   {  temp = SHA1_SHIFT(5, a) + (b ^ c ^ d) + e + w[t] + k[1];
      e = d;
      d = c;
      c = SHA1_SHIFT(30, b);
      b = a;
      a = temp;
   };

   for(t = 40; t < 60; t++)
   {  temp = SHA1_SHIFT(5, a) + ((b & c) | (b & d) | (c & d)) + e + w[t] + k[2];
      e = d;
      d = c;
      c = SHA1_SHIFT(30, b);
      b = a;
      a = temp;
   };

   for(t = 60; t < 80; t++)
   {  temp = SHA1_SHIFT(5,a) + (b ^ c ^ d) + e + w[t] + k[3];
      e = d;
      d = c;
      c = SHA1_SHIFT(30, b);
      b = a;
      a = temp;
   };

   ctx->msg_digest[0] += a;
   ctx->msg_digest[1] += b;
   ctx->msg_digest[2] += c;
   ctx->msg_digest[3] += d;
   ctx->msg_digest[4] += e;

   ctx->msg_block_idx = 0;

   return;
}


int
tics_sha1_reset(
         tics_hash_sha1_t *            ctx )
{
   assert(ctx != NULL);

   memset(ctx, 0, sizeof(tics_hash_sha1_t));
   ctx->msg_digest[0]   = 0x67452301;
   ctx->msg_digest[1]   = 0xEFCDAB89;
   ctx->msg_digest[2]   = 0x98BADCFE;
   ctx->msg_digest[3]   = 0x10325476;
   ctx->msg_digest[4]   = 0xC3D2E1F0;

   return(TICS_SUCCESS);
}


int
tics_sha1_result(
         tics_hash_sha1_t *            ctx,
         uint8_t *                     md )
{
   tics_hash_sha1_t     res;
   int                  idx;

   assert(ctx != NULL);
   assert(md   != NULL);

   if (ctx->error)
      return(ctx->error);

   memcpy(&res, ctx, sizeof(tics_hash_sha1_t));
   tics_sha1_pad_msg(&res);
   for(idx = 0; idx < TICS_HASH_SHA1_SIZE; ++idx)
      md[idx] = res.msg_digest[idx>>2] >> 8 * ( 3 - ( idx & 0x03 ) );
   memset(&res, 0, sizeof(tics_hash_sha1_t));

   return(TICS_SUCCESS);
}


int
tics_sha1_update(
         tics_hash_sha1_t *            ctx,
         const void *                  data,
         size_t                        len )
{
   size_t      idx;

   assert(ctx != NULL);
   assert(data != NULL);

   if (len == 0)
      return(TICS_SUCCESS);

   if (ctx->error)
      return(ctx->error);

   if (len > ((0xffffffffffffffffLLU - ctx->len) >> 3))
      return(ctx->error = TICS_EMSG2BIG);

   for(idx = 0; (idx < len); idx++)
   {  ctx->msg_block[ctx->msg_block_idx++] = (((const uint8_t *)data)[idx] & 0xFF);

      ctx->len += 8;

      if (ctx->msg_block_idx == 64)
         tics_sha1_process_msg_block(ctx);
   };

   return(TICS_SUCCESS);
}


/* end of source */
