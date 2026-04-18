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


//
// hash: md5
#if defined(TEST_MD5_CTX)
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
// default
#endif


#if (TEST_HASH == TICS_HASH_MD5)
#   define TEST_DATA  data_md5
#elif (TEST_HASH == TICS_HASH_SHA1)
#   define TEST_DATA  data_sha1
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _ticsauth_test_data     test_data_t;


struct _ticsauth_test_data
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

extern test_data_t            test_digests[];


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes


#endif /* end of header */
