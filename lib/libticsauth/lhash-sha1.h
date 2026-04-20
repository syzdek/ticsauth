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
#ifndef __LIB_LIBTICSAUTH_LHASH_SHA1_H
#define __LIB_LIBTICSAUTH_LHASH_SHA1_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <sys/types.h>


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
// MARK: - Data Types

typedef struct _tics_hash_ctx_sha1     tics_hash_sha1_t;


struct _tics_hash_ctx_sha1
{  uint32_t                msg_digest[6];       // message digest
   uint64_t                len;                 // message length in bits
   int32_t                 msg_block_idx;       // Index into message block array
   int32_t                 error;               // error computing digest
   uint8_t                 msg_block[64];       // 512-bit message blocks
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

extern void *
tics_sha1(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len );


extern int
tics_sha1_reset(
         tics_hash_sha1_t *            ctx );


extern int
tics_sha1_result(
         tics_hash_sha1_t *            ctx,
         uint8_t *                     md );


extern int
tics_sha1_update(
         tics_hash_sha1_t *            ctx,
         const void *                  data,
         size_t                        data_len );


#endif /* end of header */
