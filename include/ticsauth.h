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
#ifndef __TICSAUTH_H
#define __TICSAUTH_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <sys/time.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stddef.h>


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#undef _TICS_I
#undef _TICS_F
#undef _TICS_V
#ifdef _LIB_LIBTICSAUTH_H
#  define _TICS_I       inline
#  define _TICS_F       /* empty */
#  define _TICS_V       extern
#else
#  define _TICS_I       extern
#  define _TICS_F       extern
#  define _TICS_V       extern
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#define TICS_SUCCESS                0
#define TICS_EUNKNOWN               -1
#define TICS_EARGS                  -2
#define TICS_ENOMEM                 -4
#define TICS_EMSG2BIG               -5
#define TICS_EALGO                  -6
#define TICS_EMDMATCH               -7
#define TICS_EHMACKEY               -8
#define TICS_EMDBUFF                -9
#define TICS_EENCODING              -10
#define TICS_EBADDATA               -11
#define TICS_EBUFFSIZE              -12

#define TICS_ENCODE_BASE16          16
#define TICS_ENCODE_BASE32          32
#define TICS_ENCODE_BASE32HEX       50 // HEX(0x32) == DECIMAL(50)
#define TICS_ENCODE_BASE64          64

#define TICS_HASH_MD5               5
#define TICS_HASH_SHA1              1
#define TICS_HASH_SHA224            224
#define TICS_HASH_SHA256            256
#define TICS_HASH_SHA384            384
#define TICS_HASH_SHA512            512

#define TICS_MD_SIZE                64
#define TICS_MD_SIZE_MD5            16
#define TICS_MD_SIZE_SHA1           20
#define TICS_MD_SIZE_SHA224         28
#define TICS_MD_SIZE_SHA256         32
#define TICS_MD_SIZE_SHA384         48
#define TICS_MD_SIZE_SHA512         64

#define TICS_HMAC_PAD_LEN           128
#define TICS_HMAC_PAD_LEN_MD5       64
#define TICS_HMAC_PAD_LEN_SHA1      64
#define TICS_HMAC_PAD_LEN_SHA224    64
#define TICS_HMAC_PAD_LEN_SHA256    64
#define TICS_HMAC_PAD_LEN_SHA384    128
#define TICS_HMAC_PAD_LEN_SHA512    128


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
// MARK: - Data Types

typedef struct _tics_hash_ctx    tics_hash_t;
typedef struct _tics_hmac_ctx    tics_hmac_t;
typedef struct _tics_encode_ctx  tics_encode_t;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

//---------------------//
// encoding prototypes //
//---------------------//
#pragma mark encoding prototypes

_TICS_F ssize_t
tics_decode(
         int                           encoding,
         const char *                  src,
         size_t                        src_len,
         void *                        dst,
         size_t                        dst_len );


_TICS_F ssize_t
tics_decoded_size(
         int                           encoding,
         size_t                        src_len );


_TICS_F ssize_t
tics_encode(
         int                           encoding,
         const void *                  src,
         size_t                        src_len,
         char *                        dst,
         size_t                        dst_len );


_TICS_F ssize_t
tics_encoded_size(
         int                           encoding,
         size_t                        src_len );


_TICS_F int
tics_encoding_block_sizes(
         int                           encoding,
         size_t *                      enc_sizep,
         size_t *                      dec_sizep );


_TICS_F ssize_t
tics_encoding_verify(
         int                           encoding,
         const void *                  src,
         size_t                        n );


//-----------------//
// hash prototypes //
//-----------------//
#pragma mark hash prototypes

_TICS_F int
tics_hash(
         int                           algo,
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len );


_TICS_F void
tics_hash_free(
         tics_hash_t *                 ctx );


_TICS_F int
tics_hash_init(
         tics_hash_t **                ctxp,
         int                           algo );


_TICS_F ssize_t
tics_hash_md2str(
         int                           algo,
         const uint8_t *               md,
         char *                        str,
         size_t                        strlen );


_TICS_F int
tics_hash_reset(
         tics_hash_t *                 ctx,
         int                           algo );


_TICS_F int
tics_hash_result(
         tics_hash_t *                 ctx,
         uint8_t *                     md,
         size_t                        md_len );


_TICS_F ssize_t
tics_hash_result_str(
         tics_hash_t *                 ctx,
         char *                        str,
         size_t                        str_len );


_TICS_F ssize_t
tics_hash_size(
         int                           algo );


_TICS_F int
tics_hash_update(
         tics_hash_t *                 ctx,
         const void *                  data,
         size_t                        len );


_TICS_F int
tics_hash_verify(
         tics_hash_t *                 ctx,
         const uint8_t *               md,
         size_t                        md_len );


_TICS_F int
tics_hash_verify_str(
         tics_hash_t *                 ctx,
         const char *                  md_str );


//-----------------//
// hmac prototypes //
//-----------------//
#pragma mark hmac prototypes

_TICS_F void *
tics_hmac(
         int                           algo,
         const void *                  key,
         size_t                        key_len,
         const void *                  data,
         size_t                        data_len,
         uint8_t *                     md,
         size_t                        md_len );


_TICS_F void
tics_hmac_free(
         tics_hmac_t *                 ctx );


_TICS_F int
tics_hmac_init(
         tics_hmac_t **                ctxp,
         int                           algo,
         const void *                  key,
         size_t                        key_len );


_TICS_F int
tics_hmac_lock_key(
         tics_hmac_t *                 ctx );


_TICS_F int
tics_hmac_reset(
         tics_hmac_t *                 ctx,
         int                           algo );


_TICS_F int
tics_hmac_reset_message(
         tics_hmac_t *                 ctx );


_TICS_F int
tics_hmac_result(
         tics_hmac_t *                 ctx,
         uint8_t *                     md,
         size_t                        md_len );


_TICS_F ssize_t
tics_hmac_result_str(
         tics_hmac_t *                 ctx,
         char *                        str,
         size_t                        str_len );


_TICS_F int
tics_hmac_update(
         tics_hmac_t *                 ctx,
         const void *                  key,
         size_t                        len );


_TICS_F int
tics_hmac_update_key(
         tics_hmac_t *                 ctx,
         const void *                  key,
         size_t                        len );


_TICS_F int
tics_hmac_verify(
         tics_hmac_t *                 ctx,
         const uint8_t *               md,
         size_t                        md_len );


_TICS_F int
tics_hmac_verify_str(
         tics_hmac_t *                 ctx,
         const char *                  md_str );


//-----------------//
// misc prototypes //
//-----------------//
#pragma mark misc prototypes

_TICS_F const char *
tics_algo2str(
         int                           algo );


_TICS_F const char *
tics_encoding2str(
         int                           encoding );


_TICS_F const char *
tics_strerror(
         int                           err );


#endif /* end of header */
