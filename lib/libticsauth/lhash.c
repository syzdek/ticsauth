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
#define __LIB_LIBTICSAUTH_LHASH_C
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

#include "lhash.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

void *
tics_hash(
         int                           algo,
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md )
{
   static uint8_t    buff[TICS_MD_SIZE];

   assert(data       != NULL);

   if (md == NULL)
      md = buff;

   switch (algo)
   {  case TICS_HASH_MD5:     return(tics_md5(data, data_len, md));
      case TICS_HASH_SHA1:    return(tics_sha1(data, data_len, md));
      case TICS_HASH_SHA224:  return(tics_sha224(data, data_len, md));
      case TICS_HASH_SHA256:  return(tics_sha256(data, data_len, md));
      default:                break;
   }

   return(NULL);
}


int
tics_hash_algo(
         tics_hash_t *                 ctx )
{
   assert(ctx != NULL);
   return((int)ctx->algo);
}


ssize_t
tics_hash_ctx_size(
         tics_hash_t *                 ctx )
{
   assert(ctx != NULL);
   return(tics_hash_size((int)ctx->algo));
}


void
tics_hash_free(
         tics_hash_t *                 ctx )
{
   if (ctx == NULL)
      return;
   memset(ctx, 0, sizeof(tics_hash_t));
   free(ctx);
   return;
}


int
tics_hash_init(
         tics_hash_t **                ctxp,
         int                           algo )
{
   int               rc;
   tics_hash_t *     ctx;

   assert(ctxp != NULL);

   if ((ctx = malloc(sizeof(tics_hash_t))) == NULL)
      return(TICS_ENOMEM);

   if ((rc = tics_hash_reset(ctx, algo)) != TICS_SUCCESS)
   {  free(ctx);
      return(rc);
   };

   *ctxp = ctx;

   return(0);
}


ssize_t
tics_hash_md2base16(
         int                           algo,
         const uint8_t *               md,
         char *                        str,
         size_t                        strlen )
{
   ssize_t        idx;
   ssize_t        md_len;

   assert(md   != NULL);
   assert(str  != NULL);

   if ((md_len = tics_hash_size(algo)) < 0)
      return(md_len);
   if (strlen < (size_t)(md_len*2))
      return(TICS_EUNKNOWN);

   for(idx = 0; (idx < md_len); idx++)
      snprintf(&str[idx*2], 3, "%02x", md[idx]);

   return(md_len);
}


int
tics_hash_reset(
         tics_hash_t *                 ctx,
         int                           algo )
{
   assert(ctx != NULL);

   algo  = (algo == TICS_HASH_SAME)
         ? (int)ctx->algo
         : algo;

   memset(ctx, 0, sizeof(tics_hash_t));

   switch (ctx->algo = algo)
   {  case TICS_HASH_MD5:     return(tics_md5_reset(&ctx->hash.md5));
      case TICS_HASH_SHA1:    return(tics_sha1_reset(&ctx->hash.sha1));
      case TICS_HASH_SHA224:  return(tics_sha224_reset(&ctx->hash.sha224));
      case TICS_HASH_SHA256:  return(tics_sha256_reset(&ctx->hash.sha256));
      default:                break;
   }

   return(TICS_EALGO);
}


int
tics_hash_result(
         tics_hash_t *                 ctx,
         uint8_t *                     md )
{
   assert(ctx != NULL);
   assert(md  != NULL);

   switch(ctx->algo)
   {  case TICS_HASH_MD5:     return(tics_md5_result(&ctx->hash.md5, md));
      case TICS_HASH_SHA1:    return(tics_sha1_result(&ctx->hash.sha1, md));
      case TICS_HASH_SHA224:  return(tics_sha224_result(&ctx->hash.sha224, md));
      case TICS_HASH_SHA256:  return(tics_sha256_result(&ctx->hash.sha256, md));
      default:                break;
   };
   return(TICS_EALGO);
}


ssize_t
tics_hash_result16(
         tics_hash_t *                 ctx,
         char *                        str,
         size_t                        strlen )
{
   int         rc;
   uint8_t     md[TICS_MD_SIZE];
   assert(ctx != NULL);
   assert(str != NULL);
   if ((rc = tics_hash_result(ctx, md)) != TICS_SUCCESS)
      return(rc);
   return(tics_hash_md2base16((int)ctx->algo, md, str, strlen));
}


ssize_t
tics_hash_size(
         int                           algo )
{
   switch(algo)
   {  case TICS_HASH_MD5:     return(TICS_MD_SIZE_MD5);
      case TICS_HASH_SHA1:    return(TICS_MD_SIZE_SHA1);
      case TICS_HASH_SHA224:  return(TICS_MD_SIZE_SHA224);
      case TICS_HASH_SHA256:  return(TICS_MD_SIZE_SHA256);
      default:                break;
   };
   return(TICS_EALGO);
}


int
tics_hash_update(
         tics_hash_t *                 ctx,
         const void *                  data,
         size_t                        len )
{
   assert(ctx  != NULL);
   assert(data != NULL);
   if (!(len))
      return(TICS_SUCCESS);
   switch(ctx->algo)
   {  case TICS_HASH_MD5:     return(tics_md5_update(&ctx->hash.md5,  data, len));
      case TICS_HASH_SHA1:    return(tics_sha1_update(&ctx->hash.sha1, data, len));
      case TICS_HASH_SHA224:  return(tics_sha224_update(&ctx->hash.sha224, data, len));
      case TICS_HASH_SHA256:  return(tics_sha256_update(&ctx->hash.sha256, data, len));
      default:                break;
   };
   return(TICS_EALGO);
}


/* end of source */
