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
#define __LIB_LIBTICSAUTH_LHASH_MD5_C
#include "libticsauth.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <string.h>
#include <assert.h>

#include "lhash-md5.h"


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#undef F
#undef G
#undef H
#undef I
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#undef ROTATE_LEFT
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#undef FF
#define FF(a, b, c, d, x, s, ac) \
   {  (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT ((a), (s)); \
      (a) += (b); \
   }

#undef GG
#define GG(a, b, c, d, x, s, ac) \
   {  (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT ((a), (s)); \
      (a) += (b); \
   }

#undef HH
#define HH(a, b, c, d, x, s, ac) \
   {  (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT ((a), (s)); \
      (a) += (b); \
   }

#undef II
#define II(a, b, c, d, x, s, ac) \
   {  (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT ((a), (s)); \
      (a) += (b); \
   }


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#undef S11
#undef S12
#undef S13
#undef S14
#define S11 7
#define S12 12
#define S13 17
#define S14 22

#undef S21
#undef S22
#undef S23
#undef S24
#define S21 5
#define S22 9
#define S23 14
#define S24 20

#undef S31
#undef S32
#undef S33
#undef S34
#define S31 4
#define S32 11
#define S33 16
#define S34 23

#undef S41
#undef S42
#undef S43
#undef S44
#define S41 6
#define S42 10
#define S43 15
#define S44 21


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

static void
tics_md5_transform(
         uint32_t                      state[4],
         const uint8_t                 block[64] );


static void
tics_md5_encode(
         unsigned char *               output,
         uint32_t *                    input,
         unsigned int                  len );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

void
tics_md5_encode(
         uint8_t *                     output,
         uint32_t *                    input,
         unsigned int                  len )
{
   unsigned       i;
   unsigned       j;

   for (i = 0, j = 0; (j < len); i++, j += 4)
   {  output[j+0] = (input[i] >>  0) & 0xff;
      output[j+1] = (input[i] >>  8) & 0xff;
      output[j+2] = (input[i] >> 16) & 0xff;
      output[j+3] = (input[i] >> 24) & 0xff;
   };

   return;
}


int
tics_md5_reset(
         tics_hash_md5_t *             ctx )
{
   assert(ctx != NULL);
   memset(ctx, 0, sizeof(tics_hash_md5_t));
   ctx->state[0] = 0x67452301;
   ctx->state[1] = 0xefcdab89;
   ctx->state[2] = 0x98badcfe;
   ctx->state[3] = 0x10325476;
   return(TICS_SUCCESS);
}


int
tics_md5_result(
         tics_hash_md5_t *             ctx,
         uint8_t *                     md )
{
   tics_hash_md5_t      res;
   uint8_t              bits[8];
   unsigned             index;
   unsigned             padLen;

   uint8_t tics_md5_padding[64] =
   {  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
   };

   assert(ctx != NULL);
   assert(md  != NULL);

   memcpy(&res, ctx, sizeof(tics_hash_md5_t));

   // Save number of bits
   tics_md5_encode(bits, res.count, 8);

   // Pad out to 56 mod 64.
   index    = (unsigned int)((res.count[0] >> 3) & 0x3f);
   padLen   = (index < 56)
            ? (56  - index)
            : (120 - index);
   tics_md5_update(&res, tics_md5_padding, padLen);

   // Append length (before padding)
   tics_md5_update (&res, bits, 8);

   // Store state in digest
   tics_md5_encode(md, res.state, 16);

   // Zeroize sensitive information.
   memset(&res, 0, sizeof(tics_hash_md5_t));

   return(TICS_SUCCESS);
}


void
tics_md5_transform(
         uint32_t                      state[4],
         const uint8_t                 block[64] )
{
   uint32_t    a;
   uint32_t    b;
   uint32_t    c;
   uint32_t    d;
   uint32_t    x[16];
   unsigned    i;
   unsigned    j;

   a = state[0];
   b = state[1];
   c = state[2];
   d = state[3];

   for (i = 0, j = 0; j < 64; i++, j += 4)
   {  x[i] =   (((uint32_t)block[j+0]) <<  0) |
               (((uint32_t)block[j+1]) <<  8) |
               (((uint32_t)block[j+2]) << 16) |
               (((uint32_t)block[j+3]) << 24);
   };

   // Round 1
   FF(a, b, c, d, x[ 0], S11, 0xd76aa478); // 1
   FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); // 2
   FF(c, d, a, b, x[ 2], S13, 0x242070db); // 3
   FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); // 4
   FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); // 5
   FF(d, a, b, c, x[ 5], S12, 0x4787c62a); // 6
   FF(c, d, a, b, x[ 6], S13, 0xa8304613); // 7
   FF(b, c, d, a, x[ 7], S14, 0xfd469501); // 8
   FF(a, b, c, d, x[ 8], S11, 0x698098d8); // 9
   FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); // 10
   FF(c, d, a, b, x[10], S13, 0xffff5bb1); // 11
   FF(b, c, d, a, x[11], S14, 0x895cd7be); // 12
   FF(a, b, c, d, x[12], S11, 0x6b901122); // 13
   FF(d, a, b, c, x[13], S12, 0xfd987193); // 14
   FF(c, d, a, b, x[14], S13, 0xa679438e); // 15
   FF(b, c, d, a, x[15], S14, 0x49b40821); // 16

   // Round 2
   GG(a, b, c, d, x[ 1], S21, 0xf61e2562); // 17
   GG(d, a, b, c, x[ 6], S22, 0xc040b340); // 18
   GG(c, d, a, b, x[11], S23, 0x265e5a51); // 19
   GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); // 20
   GG(a, b, c, d, x[ 5], S21, 0xd62f105d); // 21
   GG(d, a, b, c, x[10], S22,  0x2441453); // 22
   GG(c, d, a, b, x[15], S23, 0xd8a1e681); // 23
   GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); // 24
   GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); // 25
   GG(d, a, b, c, x[14], S22, 0xc33707d6); // 26
   GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); // 27
   GG(b, c, d, a, x[ 8], S24, 0x455a14ed); // 28
   GG(a, b, c, d, x[13], S21, 0xa9e3e905); // 29
   GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); // 30
   GG(c, d, a, b, x[ 7], S23, 0x676f02d9); // 31
   GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); // 32

   // Round 3
   HH(a, b, c, d, x[ 5], S31, 0xfffa3942); // 33
   HH(d, a, b, c, x[ 8], S32, 0x8771f681); // 34
   HH(c, d, a, b, x[11], S33, 0x6d9d6122); // 35
   HH(b, c, d, a, x[14], S34, 0xfde5380c); // 36
   HH(a, b, c, d, x[ 1], S31, 0xa4beea44); // 37
   HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); // 38
   HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); // 39
   HH(b, c, d, a, x[10], S34, 0xbebfbc70); // 40
   HH(a, b, c, d, x[13], S31, 0x289b7ec6); // 41
   HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); // 42
   HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); // 43
   HH(b, c, d, a, x[ 6], S34,  0x4881d05); // 44
   HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); // 45
   HH(d, a, b, c, x[12], S32, 0xe6db99e5); // 46
   HH(c, d, a, b, x[15], S33, 0x1fa27cf8); // 47
   HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); // 48

   // Round 4
   II(a, b, c, d, x[ 0], S41, 0xf4292244); // 49
   II(d, a, b, c, x[ 7], S42, 0x432aff97); // 50
   II(c, d, a, b, x[14], S43, 0xab9423a7); // 51
   II(b, c, d, a, x[ 5], S44, 0xfc93a039); // 52
   II(a, b, c, d, x[12], S41, 0x655b59c3); // 53
   II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); // 54
   II(c, d, a, b, x[10], S43, 0xffeff47d); // 55
   II(b, c, d, a, x[ 1], S44, 0x85845dd1); // 56
   II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); // 57
   II(d, a, b, c, x[15], S42, 0xfe2ce6e0); // 58
   II(c, d, a, b, x[ 6], S43, 0xa3014314); // 59
   II(b, c, d, a, x[13], S44, 0x4e0811a1); // 60
   II(a, b, c, d, x[ 4], S41, 0xf7537e82); // 61
   II(d, a, b, c, x[11], S42, 0xbd3af235); // 62
   II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); // 63
   II(b, c, d, a, x[ 9], S44, 0xeb86d391); // 64

   state[0] += a;
   state[1] += b;
   state[2] += c;
   state[3] += d;

   memset(x, 0, sizeof (x));

  return;
}


int
tics_md5_update(
         tics_hash_md5_t *             ctx,
         const void *                  data,
         size_t                        data_len )
{
   size_t         i;
   size_t         idx;
   size_t         part_len;

   assert(ctx != NULL);
   assert(data != NULL);

   if (data_len == 0)
      return(TICS_SUCCESS);

   // Compute number of bytes mod 64
   idx = (unsigned int)((ctx->count[0] >> 3) & 0x3F);

   // Update number of bits
   if ((ctx->count[0] += ((uint32_t)data_len << 3)) < ((uint32_t)data_len << 3))
      ctx->count[1]++;
   ctx->count[1] += ((uint32_t)data_len >> 29);

   part_len = 64 - idx;

   // Transform as many times as possible.
   if (data_len >= part_len)
   {  memcpy(&ctx->buffer[idx], data, part_len);
      tics_md5_transform(ctx->state, ctx->buffer);

      for (i = part_len; i + 63 < data_len; i += 64)
         tics_md5_transform(ctx->state, &((const uint8_t *)data)[i]);

      idx = 0;
   } else
   {  i = 0;
   };

   // Buffer remaining input
   memcpy(&ctx->buffer[idx], &((const uint8_t *)data)[i], data_len-i);

   return(TICS_SUCCESS);
}


/* end of source */
