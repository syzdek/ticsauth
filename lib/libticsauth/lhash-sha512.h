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
#ifndef __LIB_LIBTICSAUTH_LHASH_SHA512_H
#define __LIB_LIBTICSAUTH_LHASH_SHA512_H 1

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

typedef struct _tics_hash_ctx_sha512   tics_hash_sha512_t;
typedef struct _tics_hash_ctx_sha512   tics_hash_sha384_t;


struct _tics_hash_ctx_sha512
{  uint64_t                h[8];             // message digest
   uint64_t                len_high;         // message length in bits
   uint64_t                len;              // message length in bits
   uint64_t                msg_block_idx;    // Index into message block array
   uint8_t                 msg_block[128];   // 1024-bit message blocks
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

//--------------------//
// SHA-384 prototypes //
//--------------------//
#pragma mark SHA-384 prototypes

extern void *
tics_sha384(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md );


extern int
tics_sha384_reset(
         tics_hash_sha384_t *          ctx );


extern int
tics_sha384_result(
         tics_hash_sha384_t *          ctx,
         uint8_t *                     md );


extern int
tics_sha384_update(
         tics_hash_sha384_t *          ctx,
         const void *                  data,
         size_t                        data_len );


//--------------------//
// SHA-512 prototypes //
//--------------------//
#pragma mark SHA-512 prototypes

extern void *
tics_sha512(
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md );


extern int
tics_sha512_reset(
         tics_hash_sha512_t *          ctx );


extern int
tics_sha512_result(
         tics_hash_sha512_t *          ctx,
         uint8_t *                     md );


extern int
tics_sha512_update(
         tics_hash_sha512_t *          ctx,
         const void *                  data,
         size_t                        data_len );


#endif /* end of header */
