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
#define __TESTS_DATA_BASE32_C 1
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

test_encoding_t * data_base32 = (test_encoding_t [])
{
   // Public Test Vectors
   {   // RFC 4648
      .decoded       = (const uint8_t *)"",
      .encoded       = "",
      .decode_len    = 0,
      .encode_len    = 0,
   },
   {  // RFC 4648
      .decoded       = (const uint8_t *)"f",
      .encoded       = "MY======",
      .decode_len    = 1,
      .encode_len    = 8,
   },
   {  // RFC 4648
      .decoded       = (const uint8_t *)"fo",
      .encoded       = "MZXQ====",
      .decode_len    = 2,
      .encode_len    = 8,
   },
   {  // RFC 4648
      .decoded       = (const uint8_t *)"foo",
      .encoded       = "MZXW6===",
      .decode_len    = 3,
      .encode_len    = 8,
   },
   {  // RFC 4648
      .decoded       = (const uint8_t *)"foob",
      .encoded       = "MZXW6YQ=",
      .decode_len    = 4,
      .encode_len    = 8,
   },
   {  // RFC 4648
      .decoded       = (const uint8_t *)"fooba",
      .encoded       = "MZXW6YTB",
      .decode_len    = 5,
      .encode_len    = 8,
   },
   {  // RFC 4648
      .decoded       = (const uint8_t *)"foobar",
      .encoded       = "MZXW6YTBOI======",
      .decode_len    = 6,
      .encode_len    = 16,
   },

   {  .decoded       = NULL,
      .encoded       = NULL,
      .decode_len    = 0,
      .encode_len    = 0,
   }
};


/* end of source */
