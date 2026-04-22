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
#define __LIB_LIBTICSAUTH_LHMAC_C
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

#include "lhmac.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

void *
tics_hmac(
         int                           algo,
         const void *                  key,
         size_t                        key_len,
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len )
{
   tics_hmac_t       ctx;

   tics_assert(NULL, ((key))  || ((!(key))  && (!(key_len))) );
   tics_assert(NULL, ((data)) || ((!(data)) && (!(data_len))) );
   tics_assert(NULL, md != NULL);

   memset(&ctx, 0, sizeof(tics_hmac_t));

   ctx.algo = algo;

   if (!(key))
      key      = "";
   if (!(data))
      data     = "";

   if (tics_hmac_reset(&ctx, algo) != TICS_SUCCESS)
      return(NULL);
   if (tics_hmac_update_key(&ctx, key, key_len) != TICS_SUCCESS)
      return(NULL);
   if (tics_hmac_update(&ctx, data, data_len) != TICS_SUCCESS)
      return(NULL);
   if (tics_hmac_result(&ctx, md, md_len) != TICS_SUCCESS)
      return(NULL);

   return(md);
}


void
tics_hmac_free(
         tics_hmac_t *                 ctx )
{
   if (!(ctx))
      return;
   memset(ctx, 0, sizeof(tics_hmac_t));
   free(ctx);
   return;
}


int
tics_hmac_init(
         tics_hmac_t **                ctxp,
         int                           algo,
         const void *                  key,
         size_t                        key_len )
{
   int                  rc;
   tics_hmac_t *        ctx;

   tics_assert(TICS_EARGS, ctxp != NULL);
   tics_assert(TICS_EARGS, (((key)) && ((key_len))) || ((!(key)) && (!(key_len))) );

   if ((ctx = malloc(sizeof(tics_hmac_t))) == NULL)
      return(TICS_ENOMEM);
   memset(ctx, 0, sizeof(tics_hmac_t));

   if ((rc = tics_hmac_reset(ctx, algo)) != TICS_SUCCESS)
   {  tics_hmac_free(ctx);
      return(rc);
   };

   if ((key))
   {  if ((rc = tics_hmac_update_key(ctx, key, key_len)) != TICS_SUCCESS)
      {  tics_hmac_free(ctx);
         return(rc);
      };
   };

   *ctxp = ctx;

   return(0);
}


int
tics_hmac_lock_key(
         tics_hmac_t *                 ctx )
{
   int      rc;
   size_t   idx;

   tics_assert(TICS_EARGS, ctx != NULL);

   if ((ctx->flags & TICS_HMAC_KEY_LOCKED))
      return(TICS_SUCCESS);

   // initialize HMAC calculations, if needed
   ctx->flags |= TICS_HMAC_KEY_LOCKED;

   // calculate key digest if key length exceeds message digest length
   if ((ctx->flags & TICS_HMAC_KEY_HASHED))
   {  if ((rc = tics_hash_result(&ctx->hash, ctx->key, sizeof(ctx->key))) != TICS_SUCCESS)
      {  ctx->flags |= TICS_HMAC_KEYERR;
         return(rc);
      };
      ctx->key_len = ctx->md_len;
   };

   // generate ipad and opad
   for(idx = 0; (idx < ctx->pad_len); idx++)
   {  if (idx < ctx->key_len)
      {  ctx->key_ipad[idx] = ctx->key[idx] ^ 0x36;
         ctx->key_opad[idx] = ctx->key[idx] ^ 0x5c;
      } else
      {  ctx->key_ipad[idx] = 0x36;
         ctx->key_opad[idx] = 0x5c;
      };
   };

   // reset hash for use with input data
   if ((rc = tics_hash_reset(&ctx->hash, (int)ctx->algo)) != TICS_SUCCESS)
   {  ctx->flags |= TICS_HMAC_ERROR;
      return(rc);
   };

   // initialize digest using ipad
   if ((rc = tics_hash_update(&ctx->hash, ctx->key_ipad, ctx->pad_len)) != TICS_SUCCESS)
   {  ctx->flags |= TICS_HMAC_ERROR;
      return(rc);
   };

   return(TICS_SUCCESS);
}


int
tics_hmac_reset(
         tics_hmac_t *                 ctx,
         int                           algo )
{
   int      rc;
   ssize_t  md_len;

   tics_assert(TICS_EARGS, ctx != NULL);

   if ((md_len = tics_hash_size(algo)) < 0)
      return((int)md_len);

   memset(ctx, 0, sizeof(tics_hmac_t));

   // reset hash state
   if ((rc = tics_hash_reset(&ctx->hash, algo)) != TICS_SUCCESS)
      return(rc);
   ctx->algo      = algo;
   ctx->md_len    = (size_t)md_len;
   ctx->flags    &= ~TICS_HMAC_DATERR;
   ctx->pad_len   = ctx->hash.hmac_pad_len;

   return(TICS_SUCCESS);
}


int
tics_hmac_reset_message(
         tics_hmac_t *                 ctx )
{
   int rc;

   tics_assert(TICS_EARGS, ctx != NULL);

   if (!(ctx->flags & TICS_HMAC_KEY_LOCKED))
      return(TICS_SUCCESS);

   if ((rc = tics_hash_reset(&ctx->hash, (int)ctx->algo)) != TICS_SUCCESS)
      return(rc);

   if ((rc = tics_hash_update(&ctx->hash, ctx->key_ipad, ctx->pad_len)) != TICS_SUCCESS)
   {  ctx->flags |= TICS_HMAC_ERROR;
      return(rc);
   };

   ctx->flags &= ~TICS_HMAC_DATERR;

   return(TICS_SUCCESS);
}


int
tics_hmac_result(
         tics_hmac_t *                 ctx,
         uint8_t *                     md,
         size_t                        md_len )
{
   int                  rc;
   uint8_t              inner_md[TICS_MD_SIZE];
   tics_hash_t          hash;

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, md  != NULL);

   if ((ctx->flags & TICS_HMAC_ERROR))
      return(TICS_EUNKNOWN);

   memcpy(&hash, &ctx->hash, sizeof(tics_hash_t));
   if ((rc = tics_hash_result(&hash, inner_md, sizeof(inner_md))) != TICS_SUCCESS)
   {  memset(inner_md, 0, sizeof(inner_md));
      memset(&hash, 0, sizeof(tics_hash_t));
      return(rc);
   };

   if ((rc = tics_hash_reset(&hash, (int)ctx->algo)) != TICS_SUCCESS)
   {  memset(inner_md, 0, sizeof(inner_md));
      memset(&hash, 0, sizeof(tics_hash_t));
      return(rc);
   };
   if ((rc = tics_hash_update(&hash, ctx->key_opad, ctx->pad_len)) != TICS_SUCCESS)
   {  memset(inner_md, 0, sizeof(inner_md));
      memset(&hash, 0, sizeof(tics_hash_t));
      return(rc);
   };
   if ((rc = tics_hash_update(&hash, inner_md, ctx->md_len)) != TICS_SUCCESS)
   {  memset(inner_md, 0, sizeof(inner_md));
      memset(&hash, 0, sizeof(tics_hash_t));
      return(rc);
   };
   if ((rc = tics_hash_result(&hash, md, md_len)) != TICS_SUCCESS)
   {  memset(inner_md, 0, sizeof(inner_md));
      memset(&hash, 0, sizeof(tics_hash_t));
      return(rc);
   };

   memset(inner_md, 0, sizeof(inner_md));
   memset(&hash, 0, sizeof(tics_hash_t));

   return(0);
}


ssize_t
tics_hmac_result_str(
         tics_hmac_t *                 ctx,
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

   if ((rc = tics_hmac_result(ctx, md, sizeof(md))) != TICS_SUCCESS)
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


int
tics_hmac_update(
         tics_hmac_t *                 ctx,
         const void *                  data,
         size_t                        len )
{
   int         rc;

   tics_assert(TICS_EARGS, ctx  != NULL);
   tics_assert(TICS_EARGS, ((!(data)) && (!(len))) || ((data)) );

   if ((ctx->flags & TICS_HMAC_ERROR))
      return(TICS_EUNKNOWN);

   // initialize HMAC calculations, if needed
   if (!(ctx->flags & TICS_HMAC_KEY_LOCKED))
      if ((rc = tics_hmac_lock_key(ctx)) != TICS_SUCCESS)
         return(rc);

   if (!(len))
      return(TICS_SUCCESS);

   // add input data to HMAC digest
   if ((rc = tics_hash_update(&ctx->hash, data, len)) != TICS_SUCCESS)
      ctx->flags |= TICS_HMAC_DATERR;

   return(rc);
}


int
tics_hmac_update_key(
         tics_hmac_t *                 ctx,
         const void *                  key,
         size_t                        len )
{
   int            rc;

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, key != NULL);

   if ((ctx->flags & TICS_HMAC_KEY_LOCKED) != 0)
      return(TICS_EHMACKEY);
   if ((ctx->flags & TICS_HMAC_ERROR) != 0)
      return(TICS_EUNKNOWN);

   if (len == 0)
      return(0);

   if (!(ctx->flags & TICS_HMAC_KEY_HASHED))
   {  if ( (((size_t)ctx->key_len + len) <= ctx->pad_len) && (len <= ctx->pad_len) )
      {  // append to end of existing key data if room remains
         memcpy(&ctx->key[ctx->key_len], key, len);
         ctx->key_len += (uint32_t)len;
      } else
      {  // add any existing key data to hash
         if (ctx->key_len > 0)
         {  if ((rc = tics_hash_update(&ctx->hash, ctx->key, ctx->key_len)) != TICS_SUCCESS)
            {  ctx->flags |= TICS_HMAC_KEYERR;
               return(rc);
            };
         };
         ctx->key_len = ctx->hash.md_len;
         ctx->flags     |= TICS_HMAC_KEY_HASHED;
      };
   };

   // enter additional key data to hash
   if ((ctx->flags & TICS_HMAC_KEY_HASHED))
   {  if ((rc = tics_hash_update(&ctx->hash, key, len)) != TICS_SUCCESS)
      {  ctx->flags |= TICS_HMAC_ERROR;
         return(rc);
      };
   };

   return(0);
}


int
tics_hmac_verify(
         tics_hmac_t *                 ctx,
         const uint8_t *               md,
         size_t                        md_len )
{
   int            rc;
   uint8_t        res[TICS_MD_SIZE];

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, md  != NULL);

   if (md_len != ctx->hash.md_len)
      return(TICS_EMDMATCH);

   if ((rc = tics_hmac_result(ctx, res, sizeof(res))) != TICS_SUCCESS)
      return(rc);

   if ((memcmp(md, res, ctx->md_len)))
      return(TICS_EMDMATCH);

   return(TICS_SUCCESS);
}


int
tics_hmac_verify_str(
         tics_hmac_t *                 ctx,
         const char *                  md_str )
{
   ssize_t        rc;
   char           res[(TICS_MD_SIZE*2)+1];

   tics_assert(TICS_EARGS, ctx != NULL);
   tics_assert(TICS_EARGS, md_str  != NULL);

   if ((rc = tics_hmac_result_str(ctx, res, sizeof(res))) != TICS_SUCCESS)
      return((int)rc);

   if ((strcmp(md_str, res)))
      return(TICS_EMDMATCH);

   return(TICS_SUCCESS);
}



/* end of source */
