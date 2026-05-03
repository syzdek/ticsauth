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
#define __TESTS_DATA_CRC32_C 1
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

test_digest_t * data_crc32 = (test_digest_t [])
{
   // Public Test Vectors
   {  .digest        = "00000000",
      .hmac          = NULL,
      .data          = (const uint8_t *)"",
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 1,
   },
   {  .digest        = "e8b7be43",
      .hmac          = NULL,
      .data          = (const uint8_t *)"a",
      .key           = NULL,
      .data_len      = 1,
      .key_len       = 0,
      .repeat        = 1,
   },
   {  .digest        = "352441c2",
      .hmac          = NULL,
      .data          = (const uint8_t *)"abc",
      .key           = NULL,
      .data_len      = 3,
      .key_len       = 0,
      .repeat        = 1,
   },
   {  .digest        = "20159d7f",
      .hmac          = NULL,
      .data          = (const uint8_t *)"message digest",
      .key           = NULL,
      .data_len      = 14,
      .key_len       = 0,
      .repeat        = 1,
   },
   {  .digest        = "cbf43926",
      .hmac          = NULL,
      .data          = (const uint8_t *)"123456789",
      .key           = NULL,
      .data_len      = 9,
      .key_len       = 0,
      .repeat        = 1,
   },
   {  .digest        = "4c2750bd",
      .hmac          = NULL,
      .data          = (const uint8_t *)"abcdefghijklmnopqrstuvwxyz",
      .key           = NULL,
      .data_len      = 26,
      .key_len       = 0,
      .repeat        = 1,
   },
   {  .digest        = "414fa339",
      .hmac          = NULL,
      .data          = (const uint8_t *)"The quick brown fox jumps over the lazy dog",
      .key           = NULL,
      .data_len      = 43,
      .key_len       = 0,
      .repeat        = 1,
   },


   {  .digest        = NULL,
      .hmac          = NULL,
      .data          = NULL,
      .key           = NULL,
      .data_len      = 0,
      .key_len       = 0,
      .repeat        = 0
   }
};


/* end of source */
