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
#define __LIB_LIBTICSAUTH_LENCODINGC
#include "libticsauth.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#define TICS_ENC_SIZE_BASE16        2
#define TICS_ENC_SIZE_BASE32        8
#define TICS_ENC_SIZE_BASE64        4

#define TICS_DEC_SIZE_BASE16        1
#define TICS_DEC_SIZE_BASE32        5
#define TICS_DEC_SIZE_BASE64        3


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
// MARK: - Data Types

typedef struct _tics_basexx         tics_basexx_t;

struct _tics_basexx
{  size_t                           block_enc;
   size_t                           block_dec;
   const char *                     map_chars;
   const int8_t *                   map_vals;
   ssize_t(*func_dec)(const int8_t *, const uint8_t *, size_t, uint8_t *);
   ssize_t(*func_enc)(const char *, const uint8_t *, size_t, char *);
   ssize_t(*func_verify)(const int8_t *, const uint8_t *, size_t);
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

static inline ssize_t
tics_base16_decode(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len,
         uint8_t *                     dst );


static inline ssize_t
tics_base16_encode(
         const char *                  map,
         const uint8_t *               src,
         size_t                        src_len,
         char *                        dst );


static inline ssize_t
tics_base16_verify(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len );


static inline ssize_t
tics_base32_decode(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len,
         uint8_t *                     dst );


static inline ssize_t
tics_base32_encode(
         const char *                  map,
         const uint8_t *               src,
         size_t                        src_len,
         char *                        dst );


static inline ssize_t
tics_base32_verify(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len );


static inline ssize_t
tics_base64_decode(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len,
         uint8_t *                     dst );


static inline ssize_t
tics_base64_encode(
         const char *                  map,
         const uint8_t *               src,
         size_t                        src_len,
         char *                        dst );


static inline ssize_t
tics_base64_verify(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len );


static inline int
tics_encoding(
         int                           encoding,
         tics_basexx_t *               bxx );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
// MARK: - Variables

// MARK: base16
static const int8_t * base16_vals = (const int8_t [])
{
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 0x30
   -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x40
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x50
   -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x60
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base16_chars = "0123456789abcdef";


// MARK: base32
static const int8_t * base32_vals = (const int8_t [])
{
//    This map cheats and interprets:
//       - the numeral zero as the letter "O" as in oscar
//       - the numeral one as the letter "L" as in lima
//       - the numeral eight as the letter "B" as in bravo
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
   14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";


// MARK: base32hex
static const int8_t * base32hex_vals = (const int8_t [])
{
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1,  0, -1, -1, // 0x30
   -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, // 0x40
   25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x50
   -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, // 0x60
   25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base32hex_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUV=";


// MARK: base64
static const int8_t * base64_vals = (const int8_t [])
{
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, // 0x20
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,  0, -1, -1, // 0x30
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
   -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 0x60
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

//-------------------//
// common prototypes //
//-------------------//
#pragma mark common prototypes

ssize_t
tics_decode(
         int                           encoding,
         const char *                  src,
         size_t                        src_len,
         void *                        dst,
         size_t                        dst_len )
{
   ssize_t           rc;
   size_t            len;
   tics_basexx_t     bxx;

   tics_assert(TICS_EARGS, src != NULL);
   tics_assert(TICS_EARGS, dst != NULL);

   if ((rc = tics_encoding(encoding, &bxx)) != TICS_SUCCESS)
      return(rc);

   len = (src_len / bxx.block_enc) * bxx.block_dec;
   len++;
   if ((src_len % bxx.block_enc))
      len += bxx.block_dec;

   if (dst_len < len)
      return(TICS_EBUFFSIZE);

   if ((rc = bxx.func_verify(bxx.map_vals, (const uint8_t *)src, src_len)) < TICS_SUCCESS)
      return(rc);

   ((uint8_t *)dst)[len] = '\0';

   return(bxx.func_dec(bxx.map_vals, (const uint8_t *)src, src_len, dst));
}


ssize_t
tics_decoded_size(
         int                           encoding,
         size_t                        src_len )
{
   ssize_t           rc;
   size_t            s;
   tics_basexx_t     bxx;

   if ((rc = tics_encoding(encoding, &bxx)) != TICS_SUCCESS)
      return(rc);

   s = (src_len / bxx.block_enc) * bxx.block_dec;
   if ((src_len % bxx.block_enc))
      s += bxx.block_dec;

   return(s);
}


ssize_t
tics_encode(
         int                           encoding,
         const void *                  src,
         size_t                        src_len,
         char *                        dst,
         size_t                        dst_len )
{
   ssize_t           rc;
   size_t            len;
   tics_basexx_t     bxx;

   tics_assert(TICS_EARGS, src != NULL);
   tics_assert(TICS_EARGS, dst != NULL);

   if ((rc = tics_encoding(encoding, &bxx)) != TICS_SUCCESS)
      return(rc);

   len = (src_len / bxx.block_dec) * bxx.block_enc;
   if ((src_len % bxx.block_dec))
      len += bxx.block_enc;

   if (dst_len < len)
      return(TICS_EBUFFSIZE);

   return(bxx.func_enc(bxx.map_chars, src, src_len, dst));
}


ssize_t
tics_encoded_size(
         int                           encoding,
         size_t                        src_len )
{
   ssize_t           rc;
   size_t            s;
   tics_basexx_t     bxx;

   if ((rc = tics_encoding(encoding, &bxx)) != TICS_SUCCESS)
      return(rc);

   s = (src_len / bxx.block_dec) * bxx.block_enc;
   if ((src_len % bxx.block_dec))
      s += bxx.block_enc;

   return(s);
}


int
tics_encoding(
         int                           encoding,
         tics_basexx_t *               bxx )
{
   assert(bxx != NULL);
   switch(encoding)
   {  case TICS_ENCODE_BASE16:
         bxx->map_chars       = base16_chars;
         bxx->map_vals        = base16_vals;
         bxx->block_dec       = TICS_DEC_SIZE_BASE16;
         bxx->block_enc       = TICS_ENC_SIZE_BASE16;
         bxx->func_dec        = &tics_base16_decode;
         bxx->func_enc        = &tics_base16_encode;
         bxx->func_verify     = &tics_base16_verify;
         break;

      case TICS_ENCODE_BASE32:
         bxx->map_chars       = base32_chars;
         bxx->map_vals        = base32_vals;
         bxx->block_dec       = TICS_DEC_SIZE_BASE32;
         bxx->block_enc       = TICS_ENC_SIZE_BASE32;
         bxx->func_dec        = &tics_base32_decode;
         bxx->func_enc        = &tics_base32_encode;
         bxx->func_verify     = &tics_base32_verify;
         break;

      case TICS_ENCODE_BASE32HEX:
         bxx->map_chars       = base32hex_chars;
         bxx->map_vals        = base32hex_vals;
         bxx->block_dec       = TICS_DEC_SIZE_BASE32;
         bxx->block_enc       = TICS_ENC_SIZE_BASE32;
         bxx->func_dec        = &tics_base32_decode;
         bxx->func_enc        = &tics_base32_encode;
         bxx->func_verify     = &tics_base32_verify;
         break;

      case TICS_ENCODE_BASE64:
         bxx->map_chars       = base64_chars;
         bxx->map_vals        = base64_vals;
         bxx->block_dec       = TICS_DEC_SIZE_BASE64;
         bxx->block_enc       = TICS_ENC_SIZE_BASE64;
         bxx->func_dec        = &tics_base64_decode;
         bxx->func_enc        = &tics_base64_encode;
         bxx->func_verify     = &tics_base64_verify;
         break;

      default:
         return(TICS_EENCODING);
   };
   return(TICS_SUCCESS);
}


int
tics_encoding_block_sizes(
         int                           encoding,
         size_t *                      enc_sizep,
         size_t *                      dec_sizep )
{
   int               rc;
   tics_basexx_t     bxx;

   if ((rc = tics_encoding(encoding, &bxx)) != TICS_SUCCESS)
      return(rc);

   if ((enc_sizep))
      *enc_sizep = bxx.block_enc;
   if ((dec_sizep))
      *dec_sizep = bxx.block_dec;

   return(TICS_SUCCESS);
}


ssize_t
tics_encoding_verify(
         int                           encoding,
         const void *                  src,
         size_t                        n )
{
   int               rc;
   tics_basexx_t     bxx;


   if ((rc = tics_encoding(encoding, &bxx)) != TICS_SUCCESS)
      return(rc);

   return(bxx.func_verify(bxx.map_vals, src, n));
}


//-------------------//
// base16 prototypes //
//-------------------//
#pragma mark base16 prototypes

ssize_t
tics_base16_decode(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len,
         uint8_t *                     dst )
{
   size_t      s;
   size_t      d;
   int8_t      val;

   assert(src != NULL);
   assert(dst != NULL);

   for(s = 0, d = 0; (s < src_len); d++)
   {  if ((val = map[src[s++]]) == -1)
         return(TICS_EBADDATA);
      dst[d] = val << 4;
      if ((val = map[src[s++]]) == -1)
         return(TICS_EBADDATA);
      dst[d] |= val & 0x0f;
   };

   return((ssize_t)d);
}


ssize_t
tics_base16_encode(
         const char *                  map,
         const uint8_t *               src,
         size_t                        src_len,
         char *                        dst )
{
   size_t      s;
   size_t      d;
   uint8_t     val;

   assert(src != NULL);
   assert(dst != NULL);

   for(s = 0, d = 0; (s < src_len); s++)
   {  val      = src[s];
      dst[d++] = map[val >> 4];
      dst[d++] = map[val & 0x0f];
   };

   return((ssize_t)d);
}


ssize_t
tics_base16_verify(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len )
{
   size_t   pos;
   size_t   len;

   assert(map != NULL);
   assert(src != NULL);

   len = 0;

   if ((src_len & 0x01))
      return(TICS_EBADDATA);

   // verifies encoded data contains only valid characters
   for(pos = 0; (pos < src_len); pos++)
   {  // verify that data is valid character
      if (map[src[pos]] == -1)
         return(TICS_EBADDATA);
   };

   if (!(len))
      len = pos;

   return(len / 2);
}


//-------------------//
// base32 prototypes //
//-------------------//
#pragma mark base32 prototypes

ssize_t
tics_base32_decode(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len,
         uint8_t *                     dst )
{
   size_t      pos;
   size_t      len;

   assert(src != NULL);
   assert(dst != NULL);

   // decodes base32 encoded data
   len = 0;
   for(pos = 0; (pos < src_len); pos++)
   {  // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(pos & 0x07)
      {  case 1: // byte 0
            dst[len]  = (map[src[pos-1]] << 3) & 0xF8; // 5 MSB
            dst[len] |= (map[src[pos-0]] >> 2) & 0x07; // 3 LSB
            len++;
            break;

         case 2: // byte 2
            if (src[pos] == '=')
               return((ssize_t)len);
            break;

         case 3: // byte 3
            dst[len]  = (map[src[pos-2]] << 6) & 0xC0; // 2 MSB
            dst[len] |= (map[src[pos-1]] << 1) & 0x3E; // 5  MB
            dst[len] |= (map[src[pos-0]] >> 4) & 0x01; // 1 LSB
            len++;
            break;

         case 4: // byte 4
            if (src[pos] == '=')
               return((ssize_t)len);
            dst[len]  = (map[src[pos-1]] << 4) & 0xF0; // 4 MSB
            dst[len] |= (map[src[pos-0]] >> 1) & 0x0F; // 4 LSB
            len++;
            break;

         case 5: // byte 5
            if (src[pos] == '=')
               return((ssize_t)len);
            break;

         case 6: // byte 6
            dst[len]  = (map[src[pos-2]] << 7) & 0x80; // 1 MSB
            dst[len] |= (map[src[pos-1]] << 2) & 0x7C; // 5  MB
            dst[len] |= (map[src[pos-0]] >> 3) & 0x03; // 2 LSB
            len++;
            break;

         case 7: // byte 7
            if (src[pos] == '=')
               return((ssize_t)len);
            dst[len]  = (map[src[pos-1]] << 5) & 0xE0; // 3 MSB
            dst[len] |= (map[src[pos-0]] >> 0) & 0x1F; // 5 LSB
            len++;
            break;

         default:
            if (src[pos] == '=')
               return((ssize_t)len);
            break;
      };
   };

   return((ssize_t)len);
}


ssize_t
tics_base32_encode(
         const char *                  map,
         const uint8_t *               src,
         size_t                        src_len,
         char *                        dst )
{
   size_t      len;
   size_t      dpos;
   size_t      spos;
   size_t      byte;

   assert(src != NULL);
   assert(dst != NULL);

   // calculates each digit's value
   byte = 0;
   dpos = 0;
   for(spos = 0; (spos < src_len); spos++)
   {  // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(byte)
      {  case 0:
            dst[dpos++]  =  src[spos] >> 3;         // 5 MSB
            dst[dpos++]  = (src[spos] & 0x07) << 2; // 3 LSB   2 bits unused
            byte++;
            break;

         case 1:
            dst[dpos-1] |= (src[spos] >> 6) & 0x03;  // 2 MSB
            dst[dpos++]  = (src[spos] >> 1) & 0x1f ; // 5 MB
            dst[dpos++]  = (src[spos] << 4) & 0x10;  // 1 LSB   4 bits unused
            byte++;
            break;

         case 2:
            dst[dpos-1] |=  src[spos] >> 4;          // 4 MSB
            dst[dpos++]  = (src[spos] << 1) & 0x1e ; // 4 LSB   1 bits unused
            byte++;
            break;

         case 3:
            dst[dpos-1] |=  src[spos] >> 7;          // 1 MSB
            dst[dpos++]  = (src[spos] >> 2) & 0x1f ; // 5 MB
            dst[dpos++]  = (src[spos] << 3) & 0x18 ; // 2 LSB   3 bits unused
            byte++;
            break;

         case 4:
         default:
            dst[dpos-1] |=  src[spos] >> 5;          // 3 MSB
            dst[dpos++]  =  src[spos] & 0x1f;        // 5 LSB
            byte = 0;
            break;
      };
   };

   // encodes each value
   for(len = 0; ((size_t)len) < dpos; len++)
      dst[len] = map[(uint8_t)dst[len]];

   // add padding
   for(; ((len % 8)); len++)
      dst[len] = '=';

   return((ssize_t)len);
}


ssize_t
tics_base32_verify(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len )
{
   size_t   pos;
   size_t   len;

   assert(map != NULL);
   assert(src != NULL);

   len = 0;

   // verifies encoded data contains only valid characters
   for(pos = 0; (pos < src_len); pos++)
   {  // verify that data is valid character
      if (map[src[pos]] == -1)
         return(TICS_EBADDATA);

      // verify valid use of padding
      if (src[pos] != '=')
         continue;
      if (!(len))
         len = pos;
      if ((pos % 8) < 2)
         return(TICS_EBADDATA);
      if ((pos + (8-(pos%8))) != src_len)
         return(TICS_EBADDATA);
      for(; (pos < src_len); pos++)
         if (src[pos] != '=')
            return(TICS_EBADDATA);
   };

   if (!(len))
      len = pos;

   switch(len % 8)
   {  case 0:
      case 2:
      case 4:
      case 5:
      case 7:
         break;

      case 1:
      case 3:
      case 6:
      default:
         return(TICS_EBADDATA);
   };

   return((len * 5) / 8);
}



//-------------------//
// base64 prototypes //
//-------------------//
#pragma mark base64 prototypes

ssize_t
tics_base64_decode(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len,
         uint8_t *                     dst )
{
   size_t      pos;
   size_t      len;

   assert(src != NULL);
   assert(dst != NULL);

   len = 0;
   for(pos = 0; (pos < src_len); pos++)
   {  //             Base64 Characters src[pos]           Binary bytes dst[len]
      // Step 1: src(XXXXXX 000000 000000 000000) -> dst(XXXXXX00 00000000 00000000)
      // Step 2: src(000000 XX0000 000000 000000) -> dst(000000XX 00000000 00000000)
      // Step 3: src(000000 00XXXX 000000 000000) -> dst(00000000 XXXX0000 00000000)
      // Step 4: src(000000 000000 XXXX00 000000) -> dst(00000000 0000XXXX 00000000)
      // Step 5: src(000000 000000 0000XX 000000) -> dst(00000000 00000000 XX000000)
      // Step 6: src(000000 000000 000000 XXXXXX) -> dst(00000000 00000000 00XXXXXX)
      switch(pos & 0x03)
      {  case 0:
            dst[len]    = (map[src[pos]] & 0x3f) << 2;  // Step 1
            break;

         case 1:
            dst[len++] |= (map[src[pos]] & 0x30) >> 4; // Step 2
            break;

         case 2:
            if (src[pos] == '=')
               return((ssize_t)len);
            dst[len]    = (map[src[pos-1]] & 0x0f) << 4; // Step 3
            dst[len++] |= (map[src[pos]]   & 0x3c) >> 2; // Step 4
            break;

         case 3:
         default:
            if (src[pos] == '=')
               return((ssize_t)len);
            dst[len]    = (map[src[pos-1]] & 0x03) << 6; // Step 5
            dst[len++] |= (map[src[pos]]   & 0x3f);      // Step 6
            break;
      };
   };

   return((ssize_t)len);
}


ssize_t
tics_base64_encode(
         const char *                  map,
         const uint8_t *               src,
         size_t                        src_len,
         char *                        dst )
{
   size_t      len;
   size_t      dpos;
   size_t      spos;
   size_t      byte;

   assert(src != NULL);
   assert(dst != NULL);

   byte = 0;
   dpos = 0;
   for(spos = 0; (spos < src_len); spos++)
   {  // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(byte)
      {  case 0:
            dst[dpos++]  = (src[spos] & 0xfc) >> 2;  // 6 MSB
            dst[dpos++]  = (src[spos] & 0x03) << 4;  // 2 LSB
            byte++;
            break;

         case 1:
            dst[dpos-1] |= (src[spos] & 0xf0) >> 4;  // 4 MSB
            dst[dpos++]  = (src[spos] & 0x0f) << 2;  // 4 LSB
            byte++;
            break;

         case 2:
         default:
            dst[dpos-1] |= (src[spos] & 0xc0) >> 6;  // 2 MSB
            dst[dpos++]  =  src[spos] & 0x3f;        // 6 LSB
            byte = 0;
            break;
      };
   };

   // encodes each value
   for(len = 0; ((size_t)len) < dpos; len++)
      dst[len] = map[(uint8_t)dst[len]];

   // add padding
   for(; ((len % 4)); len++)
      dst[len] = '=';

   return(len);
}


ssize_t
tics_base64_verify(
         const int8_t *                map,
         const uint8_t *               src,
         size_t                        src_len )
{
   size_t   pos;
   size_t   len;

   assert(map != NULL);
   assert(src != NULL);

   len = 0;

   // verifies encoded data contains only valid characters
   for(pos = 0; (pos < src_len); pos++)
   {  // verify that data is valid character
      if (map[src[pos]] == -1)
         return(TICS_EBADDATA);
      // verify valid use of padding
      if (src[pos] != '=')
         continue;
      if (!(len))
         len = pos;
      if ((pos % 4) < 2)
         return(-1);
      if ((pos + (4-(pos%4))) != src_len)
         return(TICS_EBADDATA);
      for(; (pos < src_len); pos++)
         if (src[pos] != '=')
            return(TICS_EBADDATA);
   };

   if (!(len))
      len = pos;

   switch(len % 4)
   {
      case 0:
      case 2:
      case 3:
       break;

      case 1:
      default:
         return(TICS_EBADDATA);
   };

   return((len * 6) / 8);
}



/* end of source */
