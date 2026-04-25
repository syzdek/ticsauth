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

int
tics_hash(
         int                           algo,
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len )
{
   int            rc;
   tics_hash_t    ctx;

   tics_assert(TICS_EARGS, ((data)) || ((!(data)) && (!(data_len))) );
   tics_assert(TICS_EARGS, md    != NULL);

   data = ((data))
        ? data
        : "";

   if ((rc = tics_hash_reset(&ctx, algo)) != TICS_SUCCESS)
      return(rc);

   if (md_len < ctx.md_len)
      return(TICS_EMDBUFF);

   if ((rc = ctx.func_update(&ctx.hash, data, data_len)) != TICS_SUCCESS)
      return(rc);

   if ((rc = ctx.func_result(&ctx.hash, md)) != TICS_SUCCESS)
      return(rc);

   memset(&ctx, 0, sizeof(tics_hash_t));

   return(TICS_SUCCESS);
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

   tics_assert(TICS_EARGS, ctxp != NULL);

   if ((ctx = malloc(sizeof(tics_hash_t))) == NULL)
      return(TICS_ENOMEM);
   memset(ctx, 0, sizeof(tics_hash_t));
   ctx->algo = algo;

   if ((rc = tics_hash_reset(ctx, algo)) != TICS_SUCCESS)
   {  tics_hash_free(ctx);
      return(rc);
   };

   *ctxp = ctx;

   return(0);
}


ssize_t
tics_hash_md2str(
         int                           algo,
         const uint8_t *               md,
         char *                        str,
         size_t                        strlen )
{
   ssize_t        idx;
   ssize_t        md_len;

   tics_assert(TICS_EARGS, md   != NULL);
   tics_assert(TICS_EARGS, str  != NULL);

   if ((md_len = tics_hash_size(algo)) < 0)
      return(md_len);
   if (strlen < (size_t)((md_len*2)+1))
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
   tics_assert(TICS_EARGS, ctx != NULL);

   memset(ctx, 0, sizeof(tics_hash_t));

   switch (ctx->algo = algo)
   {  case TICS_HASH_MD5:
         ctx->md_len          = TICS_MD_SIZE_MD5;
         ctx->hmac_pad_len    = TICS_HMAC_PAD_LEN_MD5;
         ctx->state_size      = sizeof(tics_hash_md5_t);
         ctx->func            = (void*(*)(const void*,size_t,uint8_t*,size_t))&tics_md5;
         ctx->func_reset      = (int(*)(void *))&tics_md5_reset;
         ctx->func_result     = (int(*)(void *, uint8_t *))&tics_md5_result;
         ctx->func_update     = (int(*)(void *, const void *, size_t))&tics_md5_update;
         return(tics_md5_reset(&ctx->hash.md5));

      case TICS_HASH_SHA1:
         ctx->md_len          = TICS_MD_SIZE_SHA1;
         ctx->hmac_pad_len    = TICS_HMAC_PAD_LEN_SHA1;
         ctx->state_size      = sizeof(tics_hash_sha1_t);
         ctx->func            = (void*(*)(const void*,size_t,uint8_t*,size_t))&tics_sha1;
         ctx->func_reset      = (int(*)(void *))&tics_sha1_reset;
         ctx->func_result     = (int(*)(void *, uint8_t *))&tics_sha1_result;
         ctx->func_update     = (int(*)(void *, const void *, size_t))&tics_sha1_update;
         return(tics_sha1_reset(&ctx->hash.sha1));

      case TICS_HASH_SHA224:
         ctx->md_len          = TICS_MD_SIZE_SHA224;
         ctx->hmac_pad_len    = TICS_HMAC_PAD_LEN_SHA224;
         ctx->state_size      = sizeof(tics_hash_sha224_t);
         ctx->func            = (void*(*)(const void*,size_t,uint8_t*,size_t))&tics_sha224;
         ctx->func_reset      = (int(*)(void *))&tics_sha224_reset;
         ctx->func_result     = (int(*)(void *, uint8_t *))&tics_sha224_result;
         ctx->func_update     = (int(*)(void *, const void *, size_t))&tics_sha224_update;
         return(tics_sha224_reset(&ctx->hash.sha224));

      case TICS_HASH_SHA256:
         ctx->md_len          = TICS_MD_SIZE_SHA256;
         ctx->hmac_pad_len    = TICS_HMAC_PAD_LEN_SHA256;
         ctx->state_size      = sizeof(tics_hash_sha256_t);
         ctx->func            = (void*(*)(const void*,size_t,uint8_t*,size_t))&tics_sha256;
         ctx->func_reset      = (int(*)(void *))&tics_sha256_reset;
         ctx->func_result     = (int(*)(void *, uint8_t *))&tics_sha256_result;
         ctx->func_update     = (int(*)(void *, const void *, size_t))&tics_sha256_update;
         return(tics_sha256_reset(&ctx->hash.sha256));

      case TICS_HASH_SHA384:
         ctx->md_len          = TICS_MD_SIZE_SHA384;
         ctx->hmac_pad_len    = TICS_HMAC_PAD_LEN_SHA384;
         ctx->state_size      = sizeof(tics_hash_sha384_t);
         ctx->func            = (void*(*)(const void*,size_t,uint8_t*,size_t))&tics_sha384;
         ctx->func_reset      = (int(*)(void *))&tics_sha384_reset;
         ctx->func_result     = (int(*)(void *, uint8_t *))&tics_sha384_result;
         ctx->func_update     = (int(*)(void *, const void *, size_t))&tics_sha384_update;
         return(tics_sha384_reset(&ctx->hash.sha384));

      case TICS_HASH_SHA512:
         ctx->md_len          = TICS_MD_SIZE_SHA512;
         ctx->hmac_pad_len    = TICS_HMAC_PAD_LEN_SHA512;
         ctx->state_size      = sizeof(tics_hash_sha512_t);
         ctx->func            = (void*(*)(const void*,size_t,uint8_t*,size_t))&tics_sha512;
         ctx->func_reset      = (int(*)(void *))&tics_sha512_reset;
         ctx->func_result     = (int(*)(void *, uint8_t *))&tics_sha512_result;
         ctx->func_update     = (int(*)(void *, const void *, size_t))&tics_sha512_update;
         return(tics_sha512_reset(&ctx->hash.sha512));

      default:
         break;
   }

   return(TICS_EALGO);
}


int
tics_hash_result(
         tics_hash_t *                 ctx,
         uint8_t *                     md,
         size_t                        md_len )
{
   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, md  != NULL);
   if (md_len < ctx->md_len)
      return(TICS_EMDBUFF);
   return(ctx->func_result(&ctx->hash, md));
}


ssize_t
tics_hash_result_str(
         tics_hash_t *                 ctx,
         char *                        str,
         size_t                        str_len )
{
   int            rc;
   size_t         str_pos;
   size_t         md_pos;
   uint8_t        md[TICS_MD_SIZE];
   const char *   map;

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, str != NULL);

   if (str_len < ((ctx->md_len*2)+1))
      return(TICS_EMDBUFF);

   if ((rc = tics_hash_result(ctx, md, sizeof(md))) != TICS_SUCCESS)
      return(rc);

   map = "0123456789abcdef";
   for(str_pos = 0, md_pos = 0; (md_pos < ctx->md_len); md_pos++)
   {  str[str_pos++] = map[(md[md_pos] >> 4) & 0x0f];
      str[str_pos++] = map[(md[md_pos] >> 0) & 0x0f];
   };
   str[str_pos] = '\0';

   memset(md, 0, sizeof(md));

   return((ssize_t)(ctx->md_len*2));
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
      case TICS_HASH_SHA384:  return(TICS_MD_SIZE_SHA384);
      case TICS_HASH_SHA512:  return(TICS_MD_SIZE_SHA512);
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
   tics_assert(TICS_EARGS, ctx  != NULL);
   tics_assert(TICS_EARGS, data != NULL);
   if (!(len))
      return(TICS_SUCCESS);
   return(ctx->func_update(&ctx->hash, data, len));
}


int
tics_hash_verify(
         tics_hash_t *                 ctx,
         const uint8_t *               md,
         size_t                        md_len )
{
   int            rc;
   uint8_t        res[TICS_MD_SIZE];

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, md  != NULL);

   if (md_len != ctx->md_len)
      return(TICS_EMDMATCH);

   if ((rc = tics_hash_result(ctx, res, sizeof(res))) != TICS_SUCCESS)
      return(rc);

   if ((memcmp(md, res, ctx->md_len)))
      return(TICS_EMDMATCH);

   return(TICS_SUCCESS);
}


int
tics_hash_verify_str(
         tics_hash_t *                 ctx,
         const char *                  md_str )
{
   ssize_t        rc;
   char           res[(TICS_MD_SIZE*2)+1];

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, md_str  != NULL);

   if ((rc = tics_hash_result_str(ctx, res, sizeof(res))) < TICS_SUCCESS)
      return((int)rc);

   if ((strncmp(md_str, res, (ctx->md_len*2))))
      return(TICS_EMDMATCH);
   if (md_str[ctx->md_len*2] != '\0')
      return(TICS_EMDMATCH);

   return(TICS_SUCCESS);
}

/* end of source */
