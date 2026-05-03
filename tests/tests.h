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
#ifndef __TESTS_TICSAUTH_TESTS_H
#define __TESTS_TICSAUTH_TESTS_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

// defined in the Single UNIX Specification
#ifndef _XOPEN_SOURCE
#   define _XOPEN_SOURCE 600
#endif

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <ticsauth.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#ifndef PACKAGE_BUGREPORT
#   define PACKAGE_BUGREPORT "david@syzdek.net"
#endif
#ifndef PACKAGE_COPYRIGHT
#   define PACKAGE_COPYRIGHT ""
#endif
#ifndef PACKAGE_NAME
#   define PACKAGE_NAME ""
#endif
#ifndef PACKAGE_VERSION
#   define PACKAGE_VERSION ""
#endif


#define TEST_FUNC_CTX    1
#define TEST_FUNC_SEG    2
#define TEST_FUNC_STR    3
#define TEST_FUNC_ENC    4
#define TEST_FUNC_DEC    5
#define TEST_FUNC_VER    6


//
// hash: base16
#if defined(TEST_BASE16_ENC)
#  define PROGRAM_SUFFIX      "-base16-encode"
#  define TEST_ENCODING       TICS_ENCODE_BASE16
#  define TEST_FUNC           TEST_FUNC_ENC
#elif defined(TEST_BASE16_DEC)
#  define PROGRAM_SUFFIX      "-base16-decode"
#  define TEST_ENCODING       TICS_ENCODE_BASE16
#  define TEST_FUNC           TEST_FUNC_DEC
#elif defined(TEST_BASE16_VER)
#  define PROGRAM_SUFFIX      "-base16-verify"
#  define TEST_ENCODING       TICS_ENCODE_BASE16
#  define TEST_FUNC           TEST_FUNC_VER
//
// hash: base32
#elif defined(TEST_BASE32_ENC)
#  define PROGRAM_SUFFIX      "-base32-encode"
#  define TEST_ENCODING       TICS_ENCODE_BASE32
#  define TEST_FUNC           TEST_FUNC_ENC
#elif defined(TEST_BASE32_DEC)
#  define PROGRAM_SUFFIX      "-base32-decode"
#  define TEST_ENCODING       TICS_ENCODE_BASE32
#  define TEST_FUNC           TEST_FUNC_DEC
#elif defined(TEST_BASE32_VER)
#  define PROGRAM_SUFFIX      "-base32-verify"
#  define TEST_ENCODING       TICS_ENCODE_BASE32
#  define TEST_FUNC           TEST_FUNC_VER
//
// hash: base32hex
#elif defined(TEST_BASE32HEX_ENC)
#  define PROGRAM_SUFFIX      "-base32hex-encode"
#  define TEST_ENCODING       TICS_ENCODE_BASE32HEX
#  define TEST_FUNC           TEST_FUNC_ENC
#elif defined(TEST_BASE32HEX_DEC)
#  define PROGRAM_SUFFIX      "-base32hex-decode"
#  define TEST_ENCODING       TICS_ENCODE_BASE32HEX
#  define TEST_FUNC           TEST_FUNC_DEC
#elif defined(TEST_BASE32HEX_VER)
#  define PROGRAM_SUFFIX      "-base32hex-verify"
#  define TEST_ENCODING       TICS_ENCODE_BASE32HEX
#  define TEST_FUNC           TEST_FUNC_VER
//
// hash: base64
#elif defined(TEST_BASE64_ENC)
#  define PROGRAM_SUFFIX      "-base64-encode"
#  define TEST_ENCODING       TICS_ENCODE_BASE64
#  define TEST_FUNC           TEST_FUNC_ENC
#elif defined(TEST_BASE64_DEC)
#  define PROGRAM_SUFFIX      "-base64-decode"
#  define TEST_ENCODING       TICS_ENCODE_BASE64
#  define TEST_FUNC           TEST_FUNC_DEC
#elif defined(TEST_BASE64_VER)
#  define PROGRAM_SUFFIX      "-base64-verify"
#  define TEST_ENCODING       TICS_ENCODE_BASE64
#  define TEST_FUNC           TEST_FUNC_VER
#endif


#if (TEST_ENCODING == TICS_ENCODE_BASE16)
#   define TEST_DATA  data_base16
#elif (TEST_ENCODING == TICS_ENCODE_BASE32)
#   define TEST_DATA  data_base32
#elif (TEST_ENCODING == TICS_ENCODE_BASE32HEX)
#   define TEST_DATA  data_base32hex
#elif (TEST_ENCODING == TICS_ENCODE_BASE64)
#   define TEST_DATA  data_base64
#endif


//
// hash: crc32
#if defined(TEST_CRC32_CTX)
#  define PROGRAM_SUFFIX      "-crc32-ctx"
#  define TEST_HASH           TICS_HASH_CRC32
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_CRC32_SEG)
#  define PROGRAM_SUFFIX      "-crc32-seg"
#  define TEST_HASH           TICS_HASH_CRC32
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_CRC32_STR)
#  define PROGRAM_SUFFIX      "-crc32-str"
#  define TEST_HASH           TICS_HASH_CRC32
#  define TEST_FUNC           TEST_FUNC_STR
//
// hash: md5
#elif defined(TEST_MD5_CTX)
#  define PROGRAM_SUFFIX      "-md5-ctx"
#  define TEST_HASH           TICS_HASH_MD5
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_MD5_SEG)
#  define PROGRAM_SUFFIX      "-md5-seg"
#  define TEST_HASH           TICS_HASH_MD5
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_MD5_STR)
#  define PROGRAM_SUFFIX      "-md5-str"
#  define TEST_HASH           TICS_HASH_MD5
#  define TEST_FUNC           TEST_FUNC_STR
//
// hash: sha1
#elif defined(TEST_SHA1_CTX)
#  define PROGRAM_SUFFIX      "-sha1-ctx"
#  define TEST_HASH           TICS_HASH_SHA1
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_SHA1_SEG)
#  define PROGRAM_SUFFIX      "-sha1-seg"
#  define TEST_HASH           TICS_HASH_SHA1
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_SHA1_STR)
#  define PROGRAM_SUFFIX      "-sha1-str"
#  define TEST_HASH           TICS_HASH_SHA1
#  define TEST_FUNC           TEST_FUNC_STR
//
// hash: sha224
#elif defined(TEST_SHA224_CTX)
#  define PROGRAM_SUFFIX      "-sha224-ctx"
#  define TEST_HASH           TICS_HASH_SHA224
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_SHA224_SEG)
#  define PROGRAM_SUFFIX      "-sha224-seg"
#  define TEST_HASH           TICS_HASH_SHA224
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_SHA224_STR)
#  define PROGRAM_SUFFIX      "-sha224-str"
#  define TEST_HASH           TICS_HASH_SHA224
#  define TEST_FUNC           TEST_FUNC_STR
//
// hash: sha256
#elif defined(TEST_SHA256_CTX)
#  define PROGRAM_SUFFIX      "-sha256-ctx"
#  define TEST_HASH           TICS_HASH_SHA256
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_SHA256_SEG)
#  define PROGRAM_SUFFIX      "-sha256-seg"
#  define TEST_HASH           TICS_HASH_SHA256
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_SHA256_STR)
#  define PROGRAM_SUFFIX      "-sha256-str"
#  define TEST_HASH           TICS_HASH_SHA256
#  define TEST_FUNC           TEST_FUNC_STR
//
// hash: sha384
#elif defined(TEST_SHA384_CTX)
#  define PROGRAM_SUFFIX      "-sha384-ctx"
#  define TEST_HASH           TICS_HASH_SHA384
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_SHA384_SEG)
#  define PROGRAM_SUFFIX      "-sha384-seg"
#  define TEST_HASH           TICS_HASH_SHA384
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_SHA384_STR)
#  define PROGRAM_SUFFIX      "-sha384-str"
#  define TEST_HASH           TICS_HASH_SHA384
#  define TEST_FUNC           TEST_FUNC_STR
//
// hash: sha512
#elif defined(TEST_SHA512_CTX)
#  define PROGRAM_SUFFIX      "-sha512-ctx"
#  define TEST_HASH           TICS_HASH_SHA512
#  define TEST_FUNC           TEST_FUNC_CTX
#elif defined(TEST_SHA512_SEG)
#  define PROGRAM_SUFFIX      "-sha512-seg"
#  define TEST_HASH           TICS_HASH_SHA512
#  define TEST_FUNC           TEST_FUNC_SEG
#elif defined(TEST_SHA512_STR)
#  define PROGRAM_SUFFIX      "-sha512-str"
#  define TEST_HASH           TICS_HASH_SHA512
#  define TEST_FUNC           TEST_FUNC_STR
//
// default
#endif


#if (TEST_HASH == TICS_HASH_CRC32)
#   define TEST_DATA  data_crc32
#elif (TEST_HASH == TICS_HASH_MD5)
#   define TEST_DATA  data_md5
#elif (TEST_HASH == TICS_HASH_SHA1)
#   define TEST_DATA  data_sha1
#elif (TEST_HASH == TICS_HASH_SHA224)
#   define TEST_DATA  data_sha224
#elif (TEST_HASH == TICS_HASH_SHA256)
#   define TEST_DATA  data_sha256
#elif (TEST_HASH == TICS_HASH_SHA384)
#   define TEST_DATA  data_sha384
#elif (TEST_HASH == TICS_HASH_SHA512)
#   define TEST_DATA  data_sha512
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _ticsauth_test_encoding   test_encoding_t;
typedef struct _ticsauth_test_digest     test_digest_t;


struct _ticsauth_test_encoding
{  const uint8_t *      decoded;
   const char *         encoded;
   const void *         result;
   size_t               decode_len;
   size_t               encode_len;
   size_t               result_len;
   size_t               result_ascii;
};


struct _ticsauth_test_digest
{  const char *         digest;
   const char *         hmac;
   const uint8_t *      data;
   const uint8_t *      key;
   size_t               data_len;
   size_t               key_len;
   int                  skip_seg;
   int                  repeat;
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern int verbose;
extern int quiet;

extern test_encoding_t *      data_base16;
extern test_encoding_t *      data_base32;
extern test_encoding_t *      data_base32hex;
extern test_encoding_t *      data_base64;

extern test_digest_t *        data_crc32;
extern test_digest_t *        data_md5;
extern test_digest_t *        data_sha1;
extern test_digest_t *        data_sha224;
extern test_digest_t *        data_sha256;
extern test_digest_t *        data_sha384;
extern test_digest_t *        data_sha512;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes


#endif /* end of header */
