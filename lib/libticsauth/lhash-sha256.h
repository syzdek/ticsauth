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
#ifndef __LIB_LIBTICSAUTH_LHASH_SHA256_H
#define __LIB_LIBTICSAUTH_LHASH_SHA256_H 1

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

typedef struct _tics_hash_ctx_sha256   tics_hash_sha256_t;
typedef struct _tics_hash_ctx_sha256   tics_hash_sha224_t;


struct _tics_hash_ctx_sha256
{  uint32_t                h[8];             // message digest
   uint64_t                len;              // message length in bytes
   uint64_t                msg_block_idx;    // Index into message block array
   uint8_t                 msg_block[64];    // 512-bit message blocks
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

//--------------------//
// SHA-224 prototypes //
//--------------------//
#pragma mark SHA-224 prototypes

extern void *
tics_sha224(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len );


extern int
tics_sha224_reset(
         tics_hash_sha224_t *          ctx );


extern int
tics_sha224_result(
         tics_hash_sha224_t *          ctx,
         uint8_t *                     md );


extern int
tics_sha224_update(
         tics_hash_sha224_t *          ctx,
         const void *                  data,
         size_t                        data_len );


//--------------------//
// SHA-256 prototypes //
//--------------------//
#pragma mark SHA-256 prototypes

extern void *
tics_sha256(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len );


extern int
tics_sha256_reset(
         tics_hash_sha256_t *          ctx );


extern int
tics_sha256_result(
         tics_hash_sha256_t *          ctx,
         uint8_t *                     md );


extern int
tics_sha256_update(
         tics_hash_sha256_t *          ctx,
         const void *                  data,
         size_t                        data_len );


#endif /* end of header */
