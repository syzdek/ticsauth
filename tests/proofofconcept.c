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
#define __TESTS_PROOFOFCONCEPT_C 1
#include "tests.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <ticsauth.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#undef PROGRAM_NAME
#define PROGRAM_NAME "proofofconcept"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

extern int
main(
         int                           argc,
         char *                        argv[] );


static int
proof_of_concept(
         void );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

int verbose    = 0;
int quiet      = 0;


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

int
main(
         int                           argc,
         char *                        argv[] )
{
   int               c;
   int               opt_index;

   // getopt options
   static const char *  short_opt = "hqVv";
   static struct option long_opt[] =
   {  {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {  switch(c)
      {  case -1:       /* no more arguments */
         case 0:        /* long options toggles */
            break;

         case 'h':
            printf("Usage: %s [OPTIONS]\n", PROGRAM_NAME);
            printf("       %s [OPTIONS] <string> <digest>\n", PROGRAM_NAME);
            printf("OPTIONS:\n");
            printf("  -h, --help                print this help and exit\n");
            printf("  -q, --quiet, --silent     do not print messages\n");
            printf("  -V, --version             print version number and exit\n");
            printf("  -v, --verbose             print verbose messages\n");
            printf("\n");
            return(0);

         case 'q':
            quiet++;
            break;

         case 'V':
            printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
            printf("Written by David M. Syzdek.\n");
            return(0);

         case 'v':
            verbose++;
            break;

         case '?':
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);

         default:
            fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
      };
   };

   return( proof_of_concept() );
}


int
proof_of_concept(
         void )
{
   size_t            idx;
   const char *      key;
   const char *      data;
   size_t            key_len;
   size_t            data_len;
   uint8_t           o_key_pad[64];
   uint8_t           i_key_pad[64];
   uint8_t           md[TICS_MD_SIZE];
   tics_hash_t *     ctx;

   data     = "what do ya want for nothing?";
   data_len = strlen(data);
   key      = "Jefe";
   key_len  = strlen(key);

   printf("key:         \"%s\"\n", key);
   printf("key_len:     %zu\n", key_len);
   printf("data:        \"%s\"\n", data);
   printf("data_len:    %zu\n", data_len);

   for(idx = 0; (idx < 64); idx++)
   {  if (idx < key_len)
      {  i_key_pad[idx] = key[idx] ^ 0x36;
         o_key_pad[idx] = key[idx] ^ 0x5c;
      } else
      {  i_key_pad[idx] = 0x36;
         o_key_pad[idx] = 0x5c;
      };
   };

   printf("i_key_pad:   ");
   for(idx = 0; (idx < 64); idx++)
      printf("%02x", i_key_pad[idx]);
   printf("\n");

   printf("o_key_pad:   ");
   for(idx = 0; (idx < 64); idx++)
      printf("%02x", o_key_pad[idx]);
   printf("\n");

   tics_hash_init(&ctx, TICS_HASH_SHA1);
   tics_hash_update(ctx, i_key_pad, 64);
   tics_hash_update(ctx, data, data_len);
   tics_hash_result(ctx, md);

   printf("inner md:    ");
   for(idx = 0; (idx < TICS_MD_SIZE_SHA1); idx++)
      printf("%02x", md[idx]);
   printf("\n");

   tics_hash_reset(ctx, TICS_HASH_SHA1);
   tics_hash_update(ctx, o_key_pad, 64);
   tics_hash_update(ctx, md, TICS_MD_SIZE_SHA1);
   tics_hash_result(ctx, md);

   tics_hash_free(ctx);

   printf("md:          ");
   for(idx = 0; (idx < TICS_MD_SIZE_SHA1); idx++)
      printf("%02x", md[idx]);
   printf("\n");

   printf("\n");
   printf("known:       effcdf6ae5eb2fa2d27416d5f184df9c259a7c79\n");
   tics_hmac(TICS_HASH_SHA1, "Jefe", 4, "what do ya want for nothing?", 28, md);
   printf("md:          ");
   for(idx = 0; (idx < TICS_MD_SIZE_SHA1); idx++)
      printf("%02x", md[idx]);
   printf("\n");

   return(0);
}

/* end of source */
