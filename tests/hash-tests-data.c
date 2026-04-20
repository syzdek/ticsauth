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
#include "ticsauth-tests.h"

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

testdata_hash_t test_digests[] =
{
   // Public Test Vectors
   {  .md5           = "900150983cd24fb0d6963f7d28e17f72",           // RFC 1321
      .sha1          = "a9993e364706816aba3e25717850c26c9cd0d89d",   // RFC 3174
      .sha224        = "23097d223405d8228642a477bda255b32aadbce4"
                       "bda0b3f7e36c9da7",
      .sha256        = "ba7816bf8f01cfea414140de5dae2223b00361a3"
                       "96177a9cb410ff61f20015ad",
      .sha384        = "cb00753f45a35e8bb5a03d699ac65007272c32ab"
                       "0eded1631a8b605a43ff5bed8086072ba1e7cc23"
                       "58baeca134c825a7",
      .sha512        = "ddaf35a193617abacc417349ae20413112e6fa4e"
                       "89a97ea20a9eeee64b55d39a2192992a274fc1a8"
                       "36ba3c23a3feebbd454d4423643ce80e2a9ac94f"
                       "a54ca49f",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"abc",
   },
   {  .md5           = "8215ef0796a20bcaaae116d3876c664a",
      .sha1          = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",   // RFC 3174
      .sha224        = "75388b16512776cc5dba5da1fd890150b0c6455c"
                       "b4f58b1952522525",
      .sha256        = "248d6a61d20638b8e5c026930c3e6039a33ce459"
                       "64ff2167f6ecedd419db06c1",
      .sha384        = "3391fdddfc8dc7393707a65b1b4709397cf8b1d1"
                       "62af05abfe8f450de5f36bc6b0455a8520bc4e6f"
                       "5fe95b1fe3c8452b",
      .sha512        = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef4"
                       "68b228a8279be331a703c33596fd15c13b1b07f9"
                       "aa1d3bea57789ca031ad85c7a71dd70354ec6312"
                       "38ca3445",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)
                       "abcdbcdecdefdefgefghfghighijhi"
                       "jkijkljklmklmnlmnomnopnopq",
   },
   {  .md5           = NULL,
      .sha1          = "34aa973cd4c4daa4f61eeb2bdbad27316534016f",   // RFC 3174
      .sha224        = "20794655980c91d8bbb4c1ea97618a4bf03f4258"
                       "1948b2ee4ee7ad67",
      .sha256        = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48"
                       "a497200e046d39ccc7112cd0",
      .sha384        = "9d0e1809716474cb086e834e310a4a1ced149e9c"
                       "00f248527972cec5704c2a5b07b8b3dc38ecc4eb"
                       "ae97ddd87f3d8985",
      .sha512        = "e718483d0ce769644e2e42c7bc15b4638e1f98b1"
                       "3b2044285632a803afa973ebde0ff244877ea60a"
                       "4cb0432ce577c31beb009c5c2c49aa2e4eadb217"
                       "ad8cc09b",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1000000,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"a",
   },
   {  .md5           = NULL,
      .sha1          = "dea356a2cddd90c7a7ecedc5ebb563934f460452",   // RFC 3174
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 10,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)
                       "01234567012345670123456701234567"
                       "01234567012345670123456701234567",
   },
   {  .md5           = "0cc175b9c0f1b6a831c399e269772661",           // RFC 1321
      .sha1          = NULL,
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"a",
   },
   {  .md5           = "f96b697d7cb7938d525a2f31aaf161d0",           // RFC 1321
      .sha1          = NULL,
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"message digest",
   },
   {  .md5           = "c3fcd3d76192e4007dfb496cca67e13b",           // RFC 1321
      .sha1          = NULL,
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"abcdefghijklmnopqrstuvwxyz",
   },
   {  .md5           = "d174ab98d277d9f5a5611c2c9f419d9f",           // RFC 1321
      .sha1          = NULL,
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789",
   },
   {  .md5           = "57edf4a22be3c955ac49da2e2107b67a",           // RFC 1321
      .sha1          = NULL,
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)
                       "1234567890123456789012345678901234567890"
                       "1234567890123456789012345678901234567890",
   },
   {  .md5           = NULL,
      .sha1          = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",   // Wikipedia: SHA-1
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"The quick brown fox jumps over the lazy dog"
   },
   {  .md5           = NULL,
      .sha1          = "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",   // Wikipedia: SHA-1
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)"The quick brown fox jumps over the lazy cog"
   },
   {  .md5           = "d41d8cd98f00b204e9800998ecf8427e",           // RFC 1321
      .sha1          = "da39a3ee5e6b4b0d3255bfef95601890afd80709",   // Wikipedia: SHA-1
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)""
   },


   // misc example hashes
   {  .md5           = NULL,
      .sha1          = "a49b2446a02c645bf419f995b67091253a04a259",
      .sha224        = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df"
                       "265fc0b3",
      .sha256        = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51"
                       "afac45037afee9d1",
      .sha384        = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
                       "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
      .sha512        = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa1"
                       "7299aeadb6889018501d289e4900f7e4331b99dec4b5433a"
                       "c7d329eeb6dd26545e96e55b874be909",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)
                       "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                       "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                       // https://di-mgt.com.au/sha_testvectors.html
   },
   {  .md5           = NULL,
      .sha1          = "a49b2446 a02c645b f419f995 b6709125 3a04a259",
      .sha224        = "c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab"
                       "14e6b8df 265fc0b3",
      .sha256        = "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11"
                       "e8f07a51 afac4503 7afee9d1",
      .sha384        = "09330c33 f71147e8 3d192fc7 82cd1b47 53111b17"
                       "3b3b05d2 2fa08086 e3b0f712 fcc7c71a 557e2db9"
                       "66c3e9fa 91746039",
      .sha512        = "8e959b75 dae313da 8cf4f728 14fc143f 8f7779c6"
                       "eb9f7fa1 7299aead b6889018 501d289e 4900f7e4"
                       "331b99de c4b5433a c7d329ee b6dd2654 5e96e55b"
                       "874be909",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = TICS_EMDMATCH,
      .len           = 0,
      .key           = NULL,
      .data          = (const uint8_t *)
                       "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                       "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                       // https://di-mgt.com.au/sha_testvectors.html
   },
   //{  .md5           = NULL,
   //   .sha1          = "7789f0c9ef7bfc40d93311143dfbe69e2017f592",
   //   .sha224        = NULL,
   //   .sha256        = NULL,
   //   .sha384        = NULL,
   //   .sha512        = NULL,
   //   .hmac_md5      = NULL,
   //   .hmac_sha1     = NULL,
   //   .hmac_sha224   = NULL,
   //   .hmac_sha256   = NULL,
   //   .hmac_sha384   = NULL,
   //   .hmac_sha512   = NULL,
   //   .repeat        = 16777216,
   //   .error         = 0,
   //   .len           = 0,
   //   .key           = NULL,
   //   .data          = (const uint8_t *)
   //                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh"
   //                    "ijklmno"
   //                    // https://di-mgt.com.au/sha_testvectors.html
   //},


   // TICS Authenticator tests
   {  .md5           = "ec03f2591ed29cf879f5a0313f3a56ea",
      .sha1          = "ab942e7a66c409a67be5103548c55523be840c1e",
      .sha224        = "38e0d75c097eeeda34197b71fa53040f7a7a0dd1"
                       "e72ffa3124fdacd1",
      .sha256        = "450d1cd4da4fef1ae58b317d4ce8fa156ef73b9a"
                       "38c88b57275f075e60838a90",
      .sha384        = "f0e9f7d0f7e4eef3902bba3a440b0a348296ff97"
                       "4ec861dc012887cbe03e733883105bf5d4935356"
                       "656fd179716a312e",
      .sha512        = "6fb3b07f3f4e7cd678398c9f1cf43167a5f5ee18"
                       "8dd387d81e78f4aa9109bbdf675414f6c67277c5"
                       "97a1817d68d526595a63809248c2db990daa3460"
                       "872b40af",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 69,
      .key           = NULL,
      .data          = (const uint8_t []) {
                       0x49, 0x2e, 0x20, 0x49, 0x20, 0x61, 0x6d, 0x20, 0x74,
                       0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x79,
                       0x6f, 0x75, 0x72, 0x20, 0x47, 0x6f, 0x64, 0x3a, 0x20,
                       0x79, 0x6f, 0x75, 0x20, 0x73, 0x68, 0x61, 0x6c, 0x6c,
                       0x20, 0x6e, 0x6f, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65,
                       0x20, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x20,
                       0x47, 0x6f, 0x64, 0x73, 0x20, 0x62, 0x65, 0x66, 0x6f,
                       0x72, 0x65, 0x20, 0x6d, 0x65, 0x2e },
   },
   {  .md5           = "4605183fa35cc1a1102de09a529409d0",
      .sha1          = "25afb68bbc1e21793a552c8209a7bafe100c96e5",
      .sha224        = "2b914c27763b82c9480bb70f0d1c01515a69924f"
                       "5c576ddb17249b3e",
      .sha256        = "959fb92adf790b6ac48cd1945d75e8fedcf47100"
                       "82920ba666b96d9b8a68e542",
      .sha384        = "b1971fd812b35c7dd8e303f94ffa3b57fe69527d"
                       "a6984c13b539c2dc14d0a7f9e62496a6ce319839"
                       "f1fb175e3a05e59f",
      .sha512        = "bea1e38d769497185824083ad02a7a3d96d7d1d0"
                       "f7dbc8d822ca653ecda48b4d93e3ef5a266af3ce"
                       "3a269cc7892c68e1694363b6774b720cdd28f988"
                       "56c609db",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 61,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                       0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                       0x74, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
                       0x6e, 0x61, 0x6d, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74,
                       0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x79,
                       0x6f, 0x75, 0x72, 0x20, 0x47, 0x6f, 0x64, 0x20, 0x69,
                       0x6e, 0x20, 0x76, 0x61, 0x69, 0x6e, 0x2e },
   },
   {  .md5           = "31bffcd80085b62b2d6b8e5839a9c179",
      .sha1          = "30aead178e00f0781aa8fa6aa466de139bda3c19",
      .sha224        = "11ee4c192d1480df91616743a40c4e72480b389f"
                       "dc8bae3856aed855",
      .sha256        = "56979910b4ecf0472d7379cbe40f41bc26c4775a"
                       "396b505e2c5b1e3729c13b17",
      .sha384        = "9a3203bfe056927229310389db78729b57a90f86"
                       "e3e0ef6d76578946733e09e34918b6bb00131757"
                       "70145c1d5b2642c4",
      .sha512        = "1dd6deedc78ebe9548e69431564be54b1fd8988d"
                       "323ee75da98ce53eced6e1f698e8dbf9f21ea735"
                       "944924031e90cf79d9d9c3f40fbe049cb55f6690"
                       "796f2a49",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 42,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x49, 0x49, 0x49, 0x2e, 0x20, 0x52, 0x65, 0x6d, 0x65,
                       0x6d, 0x62, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x6b,
                       0x65, 0x65, 0x70, 0x20, 0x68, 0x6f, 0x6c, 0x79, 0x20,
                       0x74, 0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x27,
                       0x73, 0x20, 0x44, 0x61, 0x79, 0x2e },
   },
   {  .md5           = NULL,
      .sha1          = "7d8901b81994938886dcbe986dcbdd54ed9b1de1",
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 38,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x49, 0x56, 0x2e, 0x20, 0x48, 0x6f, 0x6e, 0x6f, 0x72,
                       0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x66, 0x61, 0x74,
                       0x68, 0x65, 0x72, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x79,
                       0x6f, 0x75, 0x72, 0x20, 0x6d, 0x6f, 0x74, 0x68, 0x65,
                       0x72, 0x2e },
   },
   {  .md5           = "d09069312c90a7be4c02329242113607",
      .sha1          = "e139948c1bf8a81876f9dded0c96f41d1b073c00",
      .sha224        = "9259c880d70c92abb9e3f463b8b3730855b45b43"
                       "116e1df328149dce",
      .sha256        = "f49783d8e8eebf63672dafffd61e56eb7ea5448c"
                       "791b36be5b4436f4f1455286",
      .sha384        = "ab505ea64c5337bfe71910a4106e340181ba87b8"
                       "e41481eb212f3c9cc61b43fcead25cad936be78a"
                       "9e50e5718a75007e",
      .sha512        = "36eb2e716d806fa1529e95aff710ff261a068eb3"
                       "2de85286fef059dbb89a35e3a1138fe7a68469a2"
                       "d4337f81716751c1f0cfdb482dae104c17289d84"
                       "5d7c47cd",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 22,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x56, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73, 0x68,
                       0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x6b,
                       0x69, 0x6c, 0x6c, 0x2e },
   },
   {  .md5           = "ca97a6c290f44ab1ba2ccde2589ec9d5",
      .sha1          = "afa38a7fb8db9248f16af9ca5f759b4aa4628d08",
      .sha224        = "540af96ed68e79e2ed886c39c1c640f479d070c3"
                       "a9e9d772a7499cf9",
      .sha256        = "24b5e0307f1d1c87af24b8d2457dce6e8cc23589"
                       "5cab2a984028610e192bc87e",
      .sha384        = "b17807f91b6ea46185e54a3c918d9b3b3323534c"
                       "b2d32cf010761367c3be4332907a11af5898f095"
                       "b7187a6d783e7744",
      .sha512        = "b12ce734469b53ddbe38a87e1eb67943c9a84cad"
                       "92ff922823e31dc25ba2ac62c7e396b55f68b083"
                       "1508745030fe21f8b3e80e3f93f7a3579e262530"
                       "39c85c0e",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 34,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x56, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                       0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                       0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x20, 0x61, 0x64,
                       0x75, 0x6c, 0x74, 0x65, 0x72, 0x79, 0x2e },
   },
   {  .md5           = "4791d3953c893cf26349830deba76254",
      .sha1          = "400773cf752058dab5d6c7aed6e6d663879a2ffd",
      .sha224        = "918823d59b485060fabf1918a0f93a3f77ccdf61"
                       "42aa0b145036e09b",
      .sha256        = "596f5e7c779e72ea2f94739b1f774a0026854fc3"
                       "64258758a02d118a4b5f8cfd",
      .sha384        = "3b5058d7dbc3def5c270763ff966c6fc5bb2830f"
                       "abfec7ac6fd9f37fde95506f277dd0e42bdd591e"
                       "978778b3b6f55434",
      .sha512        = "2e1fcb675b03cb42b8b0adfa23861ed281ebd0c9"
                       "e9c2d9ab2835207d4d68e8d48c68a50ff795298a"
                       "3efcec4fdfa6824b1db7dd0a61bcb3054e2fe3bb"
                       "9c16026b",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 25,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x56, 0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20,
                       0x73, 0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74,
                       0x20, 0x73, 0x74, 0x65, 0x61, 0x6c, 0x2e },
   },
   {  .md5           = "d661462d6ae06e8bfb2c4e03d7408905",
      .sha1          = "87140f68fba1dca57380a52e91fafe4dc7a5f53b",
      .sha224        = "12c53a917773152296a058751f7e2f6e0dcfd969"
                       "da3a44843dfbd6a8",
      .sha256        = "0b3e9ee9b5ee55beb1b7b91744a9b9a8b1004a0b"
                       "8ab3df139902db4d5609eaa8",
      .sha384        = "8dd65c06beff1cb386f900dcf5f1bf0a4e377037"
                       "b42088537d2b84878a8891ba3fd7f7077fe7af76"
                       "46f11a56bae68026",
      .sha512        = "c99286ea991faaa8ed1f20d1f8b5dee4367e4bb3"
                       "33abbd61c578a6d41fcba588beb3478c067deca8"
                       "6b76e3d0e29f09b56a8cf392562d4f4711742475"
                       "49d6e624",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 61,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x56, 0x49, 0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75,
                       0x20, 0x73, 0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f,
                       0x74, 0x20, 0x62, 0x65, 0x61, 0x72, 0x20, 0x66, 0x61,
                       0x6c, 0x73, 0x65, 0x20, 0x77, 0x69, 0x74, 0x6e, 0x65,
                       0x73, 0x73, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x73,
                       0x74, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6e, 0x65,
                       0x69, 0x67, 0x68, 0x62, 0x6f, 0x72, 0x2e },
   },
   {  .md5           = "c58dd549f54ee1459a0cb3d07017deb8",
      .sha1          = "ef3be2f08050593ccda0e073470b25c17c68a2f6",
      .sha224        = "5fdb795cc1d529a6e02f35d7850b9f49dda01bce"
                       "1c6d0990a875c2a2",
      .sha256        = "20ec46fe8fb6bde5bdf65e6160120842e1040149"
                       "3ba297a8f1746513fc467952",
      .sha384        = "72eb5b746c1e777e0db77504847d877ccf4d65a8"
                       "526b578d5575d0cfdb53ed19acbfd0d5147d0e68"
                       "7a1b3c8e5517f1b9",
      .sha512        = "9e7ca792206d681f6eeb5d8f48d82288eb792ad1"
                       "1a56034fce5a79f3eb2c642ea3f685b3d94fcfe4"
                       "f408c193e3b196136422415748db23917c39674b"
                       "e02ea206",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 49,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x49, 0x58, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                       0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                       0x63, 0x6f, 0x76, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75,
                       0x72, 0x20, 0x6e, 0x65, 0x69, 0x67, 0x68, 0x62, 0x6f,
                       0x72, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x73, 0x70, 0x6f,
                       0x75, 0x73, 0x65, 0x2e },
   },
   {  .md5           = NULL,
      .sha1          = "e137f51bf2a0b33d5ada2f69117c7944a0749fd8",
      .sha224        = "a7ba814e631aa599966b1ff23b79b75af7bd78a7"
                       "9910d0f0abcd3550",
      .sha256        = "797f07da5a02755f066e49bb8d1d29f978b04944"
                       "6e42a858080ba0d4536c4509",
      .sha384        = "2631684d109fcfb93a54e71c1eba405c8a4934f7"
                       "29552c7733f8e4ec9c8ba9b9b1a000950df7a5a3"
                       "6e1279f207c5223c",
      .sha512        = "32de01ef2a6b9850cea349589fe6a23839762f01"
                       "c5a60573c06f8e4ffe8f1ff54116c6e1b7a9d250"
                       "b66e69929502f61a3fb2bab655e338dcd1815df4"
                       "f8c448c6",
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .repeat        = 1,
      .error         = 0,
      .len           = 47,
      .key           = NULL,
      .data          = (const uint8_t []){
                       0x58, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73, 0x68,
                       0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63,
                       0x6f, 0x76, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x72,
                       0x20, 0x6e, 0x65, 0x69, 0x67, 0x68, 0x62, 0x6f, 0x72,
                       0xe2, 0x80, 0x99, 0x73, 0x20, 0x67, 0x6f, 0x6f, 0x64,
                       0x73, 0x2e },
   },


   {  .data          = NULL,
      .len           = 0,
      .digest        = NULL,
      .md5           = NULL,
      .sha1          = NULL,
      .sha224        = NULL,
      .sha256        = NULL,
      .sha384        = NULL,
      .sha512        = NULL,
      .hmac_md5      = NULL,
      .hmac_sha1     = NULL,
      .hmac_sha224   = NULL,
      .hmac_sha256   = NULL,
      .hmac_sha384   = NULL,
      .hmac_sha512   = NULL,
      .key           = NULL,
      .error         = 0,
      .repeat        = 0
   }
};


/* end of source */
