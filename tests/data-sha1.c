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
#define __TESTS_HASH_DATA_C 1
#include "tests.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <stdlib.h>

#include <ticsauth.h>


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

test_data_t * data_sha1 = (test_data_t [])
{
   // Public Test Vectors
   {  .data          = (const uint8_t *)"Hi There",
      .digest        = "4b3aed5f9fe40159b499536fb8a10cdf3bc62b4c",   // Generated with OpenSSL
      .hmac          = "b617318655057264e28bc0b6fb378c8ef146be00",   // RFC 2202: HMAC-SHA-1: test test case 1
      .key           = (const uint8_t []) {
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                       0x0b, 0x0b },
      .data_len      = 8,
      .key_len       = 20,
      .repeat        = 1,
   },
   {  .data          = (const uint8_t *)"what do ya want for nothing?",
      .digest        = "8f820394f95335182045da24f34de52bf8bc3432",   // Generated with OpenSSL
      .hmac          = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",   // RFC 2202: HMAC-SHA-1: test test case 2
      .key           = (const uint8_t *)"Jefe",
      .data_len      = 28,
      .key_len       = 4,
      .repeat        = 1,
   },
   {  .data          = (const uint8_t []) { 0xdd },
      .digest        = NULL,
      .hmac          = "125d7342b9ac11cd91a39af48aa17b4f63f175d3",   // RFC 2202: HMAC-SHA-1: test test case 3
      .key           = (const uint8_t []) {
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa },
      .data_len      = 1,
      .key_len       = 20,
      .repeat        = 50,
   },
   {  .data          = (const uint8_t []) { 0xcd },
      .digest        = NULL,
      .hmac          = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",   // RFC 2202: HMAC-SHA-1: test test case 4
      .key           = (const uint8_t []) {
                       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                       0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                       0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 },
      .data_len      = 1,
      .key_len       = 25,
      .repeat        = 50,
   },
   {  .data          = (const uint8_t *)"Test With Truncation",
      .digest        = "8bc9d47812a5d90d01586a1d9ab3319acbcc4ded",   // generated with OpenSSL
      .hmac          = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",   // RFC 2202: HMAC-SHA-1: test test case 5
      .key           = (const uint8_t []) {
                       0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
                       0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
                       0x0c, 0x0c },
      .data_len      = 20,
      .key_len       = 20,
      .repeat        = 1,
   },
   {  .data          = (const uint8_t *)
                       "Test Using Larger Than Block-Size Key - Hash Key First",
      .digest        = "b9868cfbffc1607730e397498055d5c790c70555",   // generated with OpenSSL
      .hmac          = "aa4ae5e15272d00e95705637ce8a3b55ed402112",   // RFC 2202: HMAC-SHA-1: test test case 6
      .key           = (const uint8_t []) {
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa },
      .data_len      = 54,
      .key_len       = 80,
      .repeat        = 1,
   },
   {  .data          = (const uint8_t *)
                       "Test Using Larger Than Block-Size Key and Larger "
                       "Than One Block-Size Data",
      .digest        = "b6b2fdcd6887406bd55ad2e5c19e08ccf5f48a45",   // generated with OpenSSL
      .hmac          = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",   // RFC 2202: HMAC-SHA-1: test test case 7
      .key           = (const uint8_t []) {
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                       0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa },
      .data_len      = 73,
      .key_len       = 80,
      .repeat        = 1,
   },
   {  .data       = (const uint8_t *)"abc",
      .digest     = "a9993e364706816aba3e25717850c26c9cd0d89d",   // RFC 3174
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t *)
                    "abcdbcdecdefdefgefghfghighijhi"
                    "jkijkljklmklmnlmnomnopnopq",
      .digest     = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",   // RFC 3174
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t *)"a",
      .digest     = "34aa973cd4c4daa4f61eeb2bdbad27316534016f",   // RFC 3174
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1000000,
   },
   {  .data       = (const uint8_t *)
                    "01234567012345670123456701234567"
                    "01234567012345670123456701234567",
      .digest     = "dea356a2cddd90c7a7ecedc5ebb563934f460452",   // RFC 3174
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 10,
   },
   {  .data       = (const uint8_t *)
                    "The quick brown fox jumps over the lazy dog",
      .digest     = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",   // Wikipedia: SHA-1
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t *)
                    "The quick brown fox jumps over the lazy cog",
      .digest     = "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",   // Wikipedia: SHA-1
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t *)"",
      .digest     = "da39a3ee5e6b4b0d3255bfef95601890afd80709",   // Wikipedia: SHA-1
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1,
   },


   // misc example hashes
   {  .data       = (const uint8_t *)
                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      .digest     = "a49b2446a02c645bf419f995b67091253a04a259",   // https://di-mgt.com.au/sha_testvectors.html
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t *)
                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh"
                    "ijklmno",
      .digest     = "7789f0c9ef7bfc40d93311143dfbe69e2017f592",      // https://di-mgt.com.au/sha_testvectors.html
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 16777216,
      .skip_seg   = 1,
   },


   // TICS Authenticator tests
   {  .data       = (const uint8_t []) {
                    0x49, 0x2e, 0x20, 0x49, 0x20, 0x61, 0x6d, 0x20, 0x74,
                    0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x79,
                    0x6f, 0x75, 0x72, 0x20, 0x47, 0x6f, 0x64, 0x3a, 0x20,
                    0x79, 0x6f, 0x75, 0x20, 0x73, 0x68, 0x61, 0x6c, 0x6c,
                    0x20, 0x6e, 0x6f, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65,
                    0x20, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x20,
                    0x47, 0x6f, 0x64, 0x73, 0x20, 0x62, 0x65, 0x66, 0x6f,
                    0x72, 0x65, 0x20, 0x6d, 0x65, 0x2e },
      .digest     = "ab942e7a66c409a67be5103548c55523be840c1e",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 69,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                    0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                    0x74, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
                    0x6e, 0x61, 0x6d, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74,
                    0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x79,
                    0x6f, 0x75, 0x72, 0x20, 0x47, 0x6f, 0x64, 0x20, 0x69,
                    0x6e, 0x20, 0x76, 0x61, 0x69, 0x6e, 0x2e },
      .digest     = "25afb68bbc1e21793a552c8209a7bafe100c96e5",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 61,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x49, 0x49, 0x49, 0x2e, 0x20, 0x52, 0x65, 0x6d, 0x65,
                    0x6d, 0x62, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x6b,
                    0x65, 0x65, 0x70, 0x20, 0x68, 0x6f, 0x6c, 0x79, 0x20,
                    0x74, 0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x27,
                    0x73, 0x20, 0x44, 0x61, 0x79, 0x2e },
      .digest     = "30aead178e00f0781aa8fa6aa466de139bda3c19",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 42,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x49, 0x56, 0x2e, 0x20, 0x48, 0x6f, 0x6e, 0x6f, 0x72,
                    0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x66, 0x61, 0x74,
                    0x68, 0x65, 0x72, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x79,
                    0x6f, 0x75, 0x72, 0x20, 0x6d, 0x6f, 0x74, 0x68, 0x65,
                    0x72, 0x2e },
      .digest     = "7d8901b81994938886dcbe986dcbdd54ed9b1de1",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 38,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x56, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73, 0x68,
                    0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x6b,
                    0x69, 0x6c, 0x6c, 0x2e },
      .digest     = "e139948c1bf8a81876f9dded0c96f41d1b073c00",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 22,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x56, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                    0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                    0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x20, 0x61, 0x64,
                    0x75, 0x6c, 0x74, 0x65, 0x72, 0x79, 0x2e },
      .digest     = "afa38a7fb8db9248f16af9ca5f759b4aa4628d08",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 34,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x56, 0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20,
                    0x73, 0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74,
                    0x20, 0x73, 0x74, 0x65, 0x61, 0x6c, 0x2e },
      .digest     = "400773cf752058dab5d6c7aed6e6d663879a2ffd",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 25,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x56, 0x49, 0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75,
                    0x20, 0x73, 0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f,
                    0x74, 0x20, 0x62, 0x65, 0x61, 0x72, 0x20, 0x66, 0x61,
                    0x6c, 0x73, 0x65, 0x20, 0x77, 0x69, 0x74, 0x6e, 0x65,
                    0x73, 0x73, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x73,
                    0x74, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6e, 0x65,
                    0x69, 0x67, 0x68, 0x62, 0x6f, 0x72, 0x2e },
      .digest     = "87140f68fba1dca57380a52e91fafe4dc7a5f53b",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 61,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x49, 0x58, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                    0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                    0x63, 0x6f, 0x76, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75,
                    0x72, 0x20, 0x6e, 0x65, 0x69, 0x67, 0x68, 0x62, 0x6f,
                    0x72, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x73, 0x70, 0x6f,
                    0x75, 0x73, 0x65, 0x2e },
      .digest     = "ef3be2f08050593ccda0e073470b25c17c68a2f6",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 49,
      .key_len    = 0,
      .repeat     = 1,
   },
   {  .data       = (const uint8_t []){
                    0x58, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73, 0x68,
                    0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63,
                    0x6f, 0x76, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x72,
                    0x20, 0x6e, 0x65, 0x69, 0x67, 0x68, 0x62, 0x6f, 0x72,
                    0xe2, 0x80, 0x99, 0x73, 0x20, 0x67, 0x6f, 0x6f, 0x64,
                    0x73, 0x2e },
      .digest     = "e137f51bf2a0b33d5ada2f69117c7944a0749fd8",
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 47,
      .key_len    = 0,
      .repeat     = 1,
   },


   {  .data       = NULL,
      .digest     = NULL,
      .hmac       = NULL,
      .key        = NULL,
      .data_len   = 0,
      .key_len    = 0,
      .repeat     = 0,
   }
};


/* end of source */
