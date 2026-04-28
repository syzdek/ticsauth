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
#define __EXAMPLES_HMAC_INCREMENTAL_C 1

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
#define PROGRAM_NAME "hmac-incremental"

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
   int               rc;
   ssize_t           idx;
   char              md_str[TICS_MD_STR_SIZE];
   ssize_t           len;
   tics_hmac_t *     ctx;

   const char * strs[] =
   {  "TICS ",
      "implements ",
      "complete ",
      "specifications",
      NULL
   };

   const char * keys[] =
   {  "by ",
      "reading ",
      "documentation",
      NULL
   };

   // getopt options
   static const char *  short_opt = "hqVv";
   static struct option long_opt[] =
   {  {"help",             no_argument,       NULL, 'h' },
      {"version",          no_argument,       NULL, 'V' },
      { NULL, 0, NULL, 0 }
   };

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {  switch(c)
      {  case -1:       /* no more arguments */
         case 0:        /* long options toggles */
            break;

         case 'h':
            printf("Usage: %s [OPTIONS]\n", PROGRAM_NAME);
            printf("OPTIONS:\n");
            printf("  -h, --help                print this help and exit\n");
            printf("  -q, --quiet, --silent     do not print messages\n");
            printf("  -V, --version             print version number and exit\n");
            printf("  -v, --verbose             print verbose messages\n");
            printf("\n");
            return(0);

         case 'V':
            printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
            printf("Written by David M. Syzdek.\n");
            return(0);

         case '?':
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);

         default:
            fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
      };
   };

   printf("String:                ");
   for(idx = 0; ((strs[idx])); idx++)
      printf("%s", strs[idx]);
   printf("\n");

   // initialize HMAC-SHA-224 context
   if ((rc = tics_hmac_init(&ctx, TICS_HASH_SHA224, keys[0], strlen(keys[0]))) != TICS_SUCCESS)
   {  fprintf(stderr, "%s: tics_hmac_init(): %s\n", PROGRAM_NAME, tics_strerror(rc));
      return(1);
   };

   // load rest of key
   for(idx = 1; ((keys[idx])); idx++)
   {  if ((rc = tics_hmac_init(&ctx, TICS_HASH_SHA224, keys[idx], strlen(keys[idx]))) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: tics_hmac_init(): %s\n", PROGRAM_NAME, tics_strerror(rc));
         tics_hmac_free(ctx);
         return(1);
      };
   };

   // locks key to prohibit adding to key (the key is automatically locked on
   // the first call to tics_hmac_update()"
   if ((rc = tics_hmac_lock_key(ctx)) != TICS_SUCCESS)
   {  fprintf(stderr, "%s: tics_hmac_lock_key(): %s\n", PROGRAM_NAME, tics_strerror(rc));
      tics_hmac_free(ctx);
      return(1);
   };

   // loop through data
   for(idx = 0, len = 0; ((strs[idx])); idx++)
   {  // generate hash digest for data already fed into hash function
      if ((rc = (int)tics_hmac_result_str(ctx, md_str, sizeof(md_str))) < TICS_SUCCESS)
      {  fprintf(stderr, "%s: tics_hmac_result_str(): %s\n", PROGRAM_NAME, tics_strerror(rc));
         tics_hmac_free(ctx);
         return(1);
      };
      printf("data %2zu bytes: Digest: %s\n", len, md_str);

      // feeds string into hash function
      if ((rc = tics_hmac_update(ctx, strs[idx], strlen(strs[idx]))) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: tics_hmac_update(): %s\n", PROGRAM_NAME, tics_strerror(rc));
         tics_hmac_free(ctx);
         return(1);
      };
      len += strlen(strs[idx]);
   };

   // generate hash digest for data fed into hash function
   if ((len = tics_hmac_result_str(ctx, md_str, sizeof(md_str))) < TICS_SUCCESS)
   {  fprintf(stderr, "%s: tics_hmac_result_str(): %s\n", PROGRAM_NAME, tics_strerror((int)len));
      tics_hmac_free(ctx);
      return(1);
   };
   printf("HMAC Digest:           %s\n", md_str);

   tics_hmac_free(ctx);

   return(0);
}


/* end of source */
