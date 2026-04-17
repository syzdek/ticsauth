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
#define __TESTS_DATA_MD5_C 1
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

test_data_t * data_md5 = (test_data_t [])
{
   // Public Test Vectors
   {  .data          = (const uint8_t *)"",
      .digest        = "d41d8cd98f00b204e9800998ecf8427e",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"a",
      .digest        = "0cc175b9c0f1b6a831c399e269772661",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"abc",
      .digest        = "900150983cd24fb0d6963f7d28e17f72",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"message digest",
      .digest        = "f96b697d7cb7938d525a2f31aaf161d0",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"abcdefghijklmnopqrstuvwxyz",
      .digest        = "c3fcd3d76192e4007dfb496cca67e13b",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789",
      .digest        = "d174ab98d277d9f5a5611c2c9f419d9f",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "1234567890123456789012345678901234567890"
                       "1234567890123456789012345678901234567890",
      .digest        = "57edf4a22be3c955ac49da2e2107b67a",           // RFC 1321
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"Hi There",
      .digest        = "5b49b515f3173e4540b7d39bb57a4482",           // generated with OpenSSL
      .hmac          = "9294727a3638bb1c13f48ef8158bfc9d",           // RFC 2104: test case 1
      .key           = (const uint8_t []) {
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b },
      .data_len      = 8,
      .key_len       = 16,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"what do ya want for nothing?",
      .digest        = "d03cb659cbf9192dcd066272249f8412",           // generated with OpenSSL
      .hmac          = "750c783e6ab0b503eaa86e310a5db738",           // RFC 2104: test case 2
      .key           = (const uint8_t *)"Jefe",
      .data_len      = 28,
      .key_len       = 4,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []) {
                       0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                       0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                       0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                       0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                       0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                       0xDD, 0xDD, 0xDD, 0xDD, 0xDD },
      .digest        = NULL,
      .hmac          = "56be34521d144c88dbb8c733f0e8b3f6",           // RFC 2104: test case 3
      .key           = (const uint8_t []) {
                       0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                       0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA },
      .data_len      = 50,
      .key_len       = 16,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []) { 0xcd },
      .digest        = NULL,
      .hmac          = "697eaf0aca3a3aea3a75164746ffaa79",           // RFC 2202: HMAC-MD5: test case 4
      .key           = (const uint8_t []) {
                       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                       0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                       0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 },
      .data_len      = 1,
      .key_len       = 25,
      .repeat        = 50,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)"Test With Truncation",
      .digest        = "dbcc9d8a88e5287213bc3556f8f8a498",           // generated with OpenSSL
      .hmac          = "56461ef2342edc00f9bab995690efd4c",           // RFC 2202: HMAC-MD5: test case 5
      .key           = (const uint8_t []) {
                       0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
                       0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c },
      .data_len      = 20,
      .key_len       = 16,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "Test Using Larger Than Block-Size Key - Hash Key First",
      .digest        = "56a77c18ed0463820dad65e9c8ebe202",           // generated with OpenSSL
      .hmac          = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",           // RFC 2202: HMAC-MD5: test case 6
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
      .data_len      = 54,
      .key_len       = 80,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "Test Using Larger Than Block-Size Key and Larger "
                       "Than One Block-Size Data",
      .digest        = "f92a4e2c416c1a9beea77368f27b1fe8",           // generated with OpenSSL
      .hmac          = "6f630fad67cda0ee1fb1f562db3aa53e",           // RFC 2202: HMAC-MD5: test case 7
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
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "abcdbcdecdefdefgefghfghighijhi"
                       "jkijkljklmklmnlmnomnopnopq",
      .digest        = "8215ef0796a20bcaaae116d3876c664a",           // unknown
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "The quick brown fox jumps over the lazy dog",
      .digest        = "9e107d9d372bb6826bd81d3542a419d6",           // Wikipedia: MD5
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t *)
                       "The quick brown fox jumps over the lazy dog.",
      .digest        = "e4d909c290d0fb1ca068ffaddf22cbd0",           // Wikipedia: MD5
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },


   // TICS Authenticator tests
   {  .data          = (const uint8_t []) {
                       0x49, 0x2e, 0x20, 0x49, 0x20, 0x61, 0x6d, 0x20, 0x74,
                       0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x79,
                       0x6f, 0x75, 0x72, 0x20, 0x47, 0x6f, 0x64, 0x3a, 0x20,
                       0x79, 0x6f, 0x75, 0x20, 0x73, 0x68, 0x61, 0x6c, 0x6c,
                       0x20, 0x6e, 0x6f, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65,
                       0x20, 0x73, 0x74, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x20,
                       0x47, 0x6f, 0x64, 0x73, 0x20, 0x62, 0x65, 0x66, 0x6f,
                       0x72, 0x65, 0x20, 0x6d, 0x65, 0x2e },
      .digest        = "ec03f2591ed29cf879f5a0313f3a56ea",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 69,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                       0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                       0x74, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
                       0x6e, 0x61, 0x6d, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74,
                       0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x79,
                       0x6f, 0x75, 0x72, 0x20, 0x47, 0x6f, 0x64, 0x20, 0x69,
                       0x6e, 0x20, 0x76, 0x61, 0x69, 0x6e, 0x2e },
      .digest        = "4605183fa35cc1a1102de09a529409d0",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 61,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x49, 0x49, 0x49, 0x2e, 0x20, 0x52, 0x65, 0x6d, 0x65,
                       0x6d, 0x62, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x6b,
                       0x65, 0x65, 0x70, 0x20, 0x68, 0x6f, 0x6c, 0x79, 0x20,
                       0x74, 0x68, 0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x27,
                       0x73, 0x20, 0x44, 0x61, 0x79, 0x2e },
      .digest        = "31bffcd80085b62b2d6b8e5839a9c179",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 42,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x49, 0x56, 0x2e, 0x20, 0x48, 0x6f, 0x6e, 0x6f, 0x72,
                       0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x66, 0x61, 0x74,
                       0x68, 0x65, 0x72, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x79,
                       0x6f, 0x75, 0x72, 0x20, 0x6d, 0x6f, 0x74, 0x68, 0x65,
                       0x72, 0x2e },
      .digest        = "d76c1007df06d2528224dfdbd7517083",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 38,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x56, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73, 0x68,
                       0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x6b,
                       0x69, 0x6c, 0x6c, 0x2e },
      .digest        = "d09069312c90a7be4c02329242113607",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 22,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x56, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                       0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                       0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x20, 0x61, 0x64,
                       0x75, 0x6c, 0x74, 0x65, 0x72, 0x79, 0x2e },
      .digest        = "ca97a6c290f44ab1ba2ccde2589ec9d5",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 34,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x56, 0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20,
                       0x73, 0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74,
                       0x20, 0x73, 0x74, 0x65, 0x61, 0x6c, 0x2e },
      .digest        = "4791d3953c893cf26349830deba76254",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 25,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x56, 0x49, 0x49, 0x49, 0x2e, 0x20, 0x59, 0x6f, 0x75,
                       0x20, 0x73, 0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f,
                       0x74, 0x20, 0x62, 0x65, 0x61, 0x72, 0x20, 0x66, 0x61,
                       0x6c, 0x73, 0x65, 0x20, 0x77, 0x69, 0x74, 0x6e, 0x65,
                       0x73, 0x73, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x73,
                       0x74, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6e, 0x65,
                       0x69, 0x67, 0x68, 0x62, 0x6f, 0x72, 0x2e },
      .digest        = "d661462d6ae06e8bfb2c4e03d7408905",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 61,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x49, 0x58, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73,
                       0x68, 0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20,
                       0x63, 0x6f, 0x76, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75,
                       0x72, 0x20, 0x6e, 0x65, 0x69, 0x67, 0x68, 0x62, 0x6f,
                       0x72, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x73, 0x70, 0x6f,
                       0x75, 0x73, 0x65, 0x2e },
      .digest        = "c58dd549f54ee1459a0cb3d07017deb8",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 49,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },
   {  .data          = (const uint8_t []){
                       0x58, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x73, 0x68,
                       0x61, 0x6c, 0x6c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63,
                       0x6f, 0x76, 0x65, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x72,
                       0x20, 0x6e, 0x65, 0x69, 0x67, 0x68, 0x62, 0x6f, 0x72,
                       0xe2, 0x80, 0x99, 0x73, 0x20, 0x67, 0x6f, 0x6f, 0x64,
                       0x73, 0x2e },
      .digest        = "309b5d72f295e0edb433ea8437dde39e",
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 47,
      .key_len       = 0,
      .repeat        = 1,
      .error         = 0,
   },


   {  .data          = NULL,
      .digest        = NULL,
      .hmac          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .error         = 0,
      .repeat        = 0
   }
};


/* end of source */
