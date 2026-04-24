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
#define __LIB_LIBTICSAUTH_LMISC_C
#include "libticsauth.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <string.h>
#include <stdlib.h>
#include <assert.h>


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

const char *
tics_algo2str(
         int                           algo )
{
   switch (algo)
   {  case TICS_HASH_MD5:     return("MD5");
      case TICS_HASH_SHA1:    return("SHA-1");
      case TICS_HASH_SHA224:  return("SHA-224");
      case TICS_HASH_SHA256:  return("SHA-256");
      case TICS_HASH_SHA384:  return("SHA-384");
      case TICS_HASH_SHA512:  return("SHA-512");
      default:                break;
   }
   return(NULL);
}


const char *
tics_strerror(
         int                           err )
{
   switch (err)
   {  case TICS_SUCCESS:   return("success");
      case TICS_EALGO:     return("unknown or unsupported algorithm");
      case TICS_EBADDATA:  return("bad data");
      case TICS_EBUFFSIZE: return("message length exceeds buffer size");
      case TICS_EENCODING: return("unknown or unsupported encoding");
      case TICS_EHMACKEY:  return("HMAC key is locked");
      case TICS_EMDBUFF:   return("message digest exceeds size of buffer");
      case TICS_EMDMATCH:  return("message digest mismatch");
      case TICS_EMSG2BIG:  return("message exceeds size limits");
      case TICS_ENOMEM:    return("cannot allocate memory");
      default:             break;
   }
   return("unknown error");
}


/* end of source */
