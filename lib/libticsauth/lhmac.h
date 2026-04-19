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
#ifndef __LIB_LIBTICSAUTH_LHMAC_H
#define __LIB_LIBTICSAUTH_LHMAC_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <sys/types.h>

#include "lhash.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#define TICS_HMAC_KEYERR         0x000001
#define TICS_HMAC_DATERR         0x000002
#define TICS_HMAC_ERROR          (TICS_HMAC_KEYERR | TICS_HMAC_DATERR)
#define TICS_HMAC_KEYED          0x000004


//////////////////
//              //
//  Data Types  //
//              //
//////////////////
// MARK: - Data Types

struct _tics_hmac_ctx
{  int64_t                          algo;
   uint64_t                         flags;
   size_t                           md_len;
   size_t                           key_len;
   size_t                           pad_len;
   uint8_t                          key_opad[TICS_HMAC_PAD_LEN];
   uint8_t                          key_ipad[TICS_HMAC_PAD_LEN];
   uint8_t                          key[TICS_MD_SIZE];
   tics_hash_t                      hash;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes


#endif /* end of header */
