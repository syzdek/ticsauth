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
#define __TESTS_TEST_HASH_C 1
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

#undef TEST_HASH_FUNC_CTX
#undef TEST_HASH_FUNC_SEG
#undef TEST_HASH_FUNC_STR
#define TEST_HASH_FUNC_CTX    1
#define TEST_HASH_FUNC_SEG    2
#define TEST_HASH_FUNC_STR    3

#undef PROGRAM_NAME
#undef TEST_FUNC_CTX
#undef TEST_FUNC_SEG
#undef TEST_FUNC_STR
#undef TEST_HASH_ALGO
#undef TEST_HASH_DATA

//
// hash: md5
#if defined(TEST_HASH_MD5_CTX)
#  define PROGRAM_NAME        "hmac-md5-ctx"
#  define TEST_HASH_ALGO      TICS_HASH_MD5
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_CTX
#elif defined(TEST_HASH_MD5_SEG)
#  define PROGRAM_NAME        "hmac-md5-seg"
#  define TEST_HASH_ALGO      TICS_HASH_MD5
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_SEG
#elif defined(TEST_HASH_MD5_STR)
#  define PROGRAM_NAME        "hmac-md5-str"
#  define TEST_HASH_ALGO      TICS_HASH_MD5
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_STR
//
// hash: sha1
#elif defined(TEST_HASH_SHA1_CTX)
#  define PROGRAM_NAME        "hmac-sha1-ctx"
#  define TEST_HASH_ALGO      TICS_HASH_SHA1
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_CTX
#elif defined(TEST_HASH_SHA1_SEG)
#  define PROGRAM_NAME        "hmac-sha1-seg"
#  define TEST_HASH_ALGO      TICS_HASH_SHA1
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_SEG
#elif defined(TEST_HASH_SHA1_STR)
#  define PROGRAM_NAME        "hmac-sha1-str"
#  define TEST_HASH_ALGO      TICS_HASH_SHA1
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_STR
//
// default
#else
#  define PROGRAM_NAME        "hash-sha1-str"
#  define TEST_HASH_ALGO      TICS_HASH_SHA1
#  define TEST_HASH_FUNC      TEST_HASH_FUNC_STR
#endif


#if (TEST_HASH_ALGO == TICS_HASH_MD5)
#   define TEST_HASH_DATA  data_md5
#elif (TEST_HASH_ALGO == TICS_HASH_SHA1)
#   define TEST_HASH_DATA  data_sha1
#else
#   define TEST_HASH_DATA  data_sha1
#endif


#define TEST_ERROR   1
#define TEST_SKIP    2


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
test_hash_ctx(
         int                           test_num,
         int                           algo,
         test_data_t *                 rec );


static void
test_hmac_result(
         const char *                  title,
         int                           test_num,
         int                           algo,
         test_data_t *                 rec,
         const char *                  digest,
         int                           err );


static int
test_hash_seg(
         int                           test_num,
         int                           algo,
         test_data_t *                 rec );


static int
test_hash_str(
         int                           test_num,
         int                           algo,
         test_data_t *                 rec );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

int verbose    = 0;
int quiet      = 0;

extern test_data_t *          data_md5;
extern test_data_t *          data_sha1;


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
   int               skipped;
   int               errors;
   int               tests;
   int               idx;
   int               rc;
   int               algo;
   int               func;
   test_data_t       rec;
   test_data_t *     data;

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

   func     = TEST_HASH_FUNC;
   algo     = TEST_HASH_ALGO;
   data     = TEST_HASH_DATA;

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {  switch(c)
      {  case -1:       /* no more arguments */
         case 0:        /* long options toggles */
            break;

         // these are not intended to be used, but rather to prevent
         // compiler warnings for unused code.
         case '0':
            func = TEST_HASH_FUNC_CTX;
            break;
         case '1':
            func = TEST_HASH_FUNC_SEG;
            break;
         case '2':
            func = TEST_HASH_FUNC_STR;
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

   tests    = 0;
   errors   = 0;
   skipped  = 0;

   // use test data from CLI
   if (argc != optind)
   {  if ((optind + 2) > argc)
      {  fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
      if (argc > (optind + 2))
      {  fprintf(stderr, "%s: unkown argument -- `%s'\n", PROGRAM_NAME, argv[optind+2]);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
      memset(&rec, 0, sizeof(rec));
      rec.data    = (const uint8_t *) argv[optind];
      rec.digest  = argv[optind+1];
      rec.repeat   = 1;
      switch(func)
      {  case TEST_HASH_FUNC_CTX:   return(test_hash_ctx(1, algo, &rec));
         case TEST_HASH_FUNC_SEG:   return(test_hash_seg(1, algo, &rec));
         case TEST_HASH_FUNC_STR:   return(test_hash_str(1, algo, &rec));
         default:
            fprintf(stderr, "%s: unknown test\n", PROGRAM_NAME);
            return(1);
      };
   };

   // use test data sets
   for(idx = 0; ((data[idx].data)); idx++)
   {  if (!(data[idx].digest))
         continue;
      tests++;
      switch(func)
      {  case TEST_HASH_FUNC_CTX:   rc = test_hash_ctx(tests, algo, &data[idx]); break;
         case TEST_HASH_FUNC_SEG:   rc = test_hash_seg(tests, algo, &data[idx]); break;
         case TEST_HASH_FUNC_STR:   rc = test_hash_str(tests, algo, &data[idx]); break;
         default:
            fprintf(stderr, "%s: unknown test\n", PROGRAM_NAME);
            return(1);
      };
      if (rc == TEST_SKIP)
         skipped++;
      if (rc == TEST_ERROR)
         errors++;
   };

   if (!(quiet))
   {  tests -= skipped;
      printf("results:\n");
      printf("    digests skipped:  %3i\n", skipped);
      printf("    digests passed:   %3i\n", (tests - errors - skipped));
      printf("    digests failed:   %3i\n", errors);
      printf("    total digests:    %3i\n", tests);
   };

   return( ((errors)) ? 1 : 0 );
}


int
test_hash_ctx(
         int                           test_num,
         int                           algo,
         test_data_t *                 rec )
{
   int               rc;
   int               err;
   int               count;
   uint8_t           md[TICS_MD_SIZE];
   char              digest[(TICS_MD_SIZE*2)+1];
   tics_hash_t *     ctx;

   assert(rec != NULL);

   err      = 0;

   memset(digest, 0, sizeof(digest));
   if (!(rec->data_len))
      for(rec->data_len = 0; ((rec->data[rec->data_len])); rec->data_len++);

   if ((rc = tics_hash_init(&ctx, algo)) != TICS_SUCCESS)
      err = rc;

   if (!(err))
      for(count = 0; ( (count < rec->repeat) && (!(err)) ); count++)
         if ((rc = tics_hash_update(ctx, rec->data, rec->data_len)) != TICS_SUCCESS)
            err = rc;

   if (!(err))
      if ((rc = tics_hash_result(ctx, md)) != TICS_SUCCESS)
         err = rc;

   if (!(err))
      tics_hash_md2base16(algo, md, digest, sizeof(digest));

   if (!(err))
      if ((strcmp(rec->digest, digest)))
         err = TICS_EMDMATCH;

   test_hmac_result("context", test_num, algo, rec, digest, err);

   return( ((err)) ? TEST_ERROR : 0 );
}


void
test_hmac_result(
         const char *                  title,
         int                           test_num,
         int                           algo,
         test_data_t *                 rec,
         const char *                  digest,
         int                           err )
{
   size_t            idx;

   if ( (!(verbose)) && (!(err)) )
      return;

   printf("%2i. %s digest %s test\n", test_num, tics_algo2str(algo), title);
   printf("    Expected: %s\n", rec->digest);
   if ( (!(err)) && (!(digest)) )
   {  printf("    skipping...\n");
      printf("\n");
      return;
   };
   printf("    Result:   %s\n", digest);
   if (verbose > 1)
   {  printf("    Data:    ");
      for(idx = 0; (idx < rec->data_len); idx++)
      {  if ( ((idx % 20) == 0) && ((idx)) )
            printf("\n             ");
         printf(" %02x", rec->data[idx]);
      };
      printf("\n");
   };
   if ( (verbose > 1) || ((err)) )
      printf("    Data Len: %zu\n", rec->data_len);
   if ((err))
      printf("    Error:    %s\n", tics_strerror(err));
   printf("\n");
}


int
test_hash_seg(
         int                           test_num,
         int                           algo,
         test_data_t *                 rec )
{
   int               rc;
   int               err;
   int               count;
   size_t            seg_len;
   size_t            len;
   size_t            idx;
   uint8_t           md[TICS_MD_SIZE];
   char              digest[(TICS_MD_SIZE*2)+1];
   tics_hash_t *     ctx;

   assert(rec != NULL);

   err   = 0;

   if ((rec->skip_seg))
   {  test_hmac_result("segment", test_num, algo, rec, NULL, err);
      return(TEST_SKIP);
   };

   memset(digest, 0, sizeof(digest));
   if (!(rec->data_len))
      for(rec->data_len = 0; ((rec->data[rec->data_len])); rec->data_len++);

   if ((rc = tics_hash_init(&ctx, algo)) != TICS_SUCCESS)
      err = rc;

   for(seg_len = 1; ( (seg_len <= rec->data_len) && (!(err)) ); seg_len++)
   {  tics_hash_reset(ctx, algo);

      for(idx = 0; (idx < rec->data_len); idx += seg_len)
      {  len = rec->data_len - idx;
         len = (len > seg_len)
             ? seg_len
             : len;
         if ((rc = tics_hash_update(ctx, &rec->data[idx], len)) != TICS_SUCCESS)
            err = rc;
      };

      for(count = 1; ( (count < rec->repeat) && (!(err)) ); count++)
         if ((rc = tics_hash_update(ctx, rec->data, rec->data_len)) != TICS_SUCCESS)
            err = rc;

      if (!(err))
         if ((rc = tics_hash_result(ctx, md)) != TICS_SUCCESS)
            err = rc;

      if (!(err))
         tics_hash_md2base16(algo, md, digest, sizeof(digest));

      if (!(err))
         if ((strcmp(rec->digest, digest)))
            err = TICS_EMDMATCH;
   };

   test_hmac_result("segment", test_num, algo, rec, digest, err);

   return( ((err)) ? TEST_ERROR : 0 );
}


int
test_hash_str(
         int                           test_num,
         int                           algo,
         test_data_t *                 rec )
{
   int               err;
   uint8_t *         res;
   uint8_t           md[TICS_MD_SIZE];
   char              digest[(TICS_MD_SIZE*2)+1];

   assert(rec != NULL);

   err = 0;

   if (rec->repeat != 1)
   {  test_hmac_result("string", test_num, algo, rec, digest, err);
      return(TEST_SKIP);
   };

   memset(digest, 0, sizeof(digest));
   if (!(rec->data_len))
      for(rec->data_len = 0; ((rec->data[rec->data_len])); rec->data_len++);

   if ((res = tics_hash(algo, rec->data, rec->data_len, md)))
   {  tics_hash_md2base16(algo, md, digest, sizeof(digest));
      if ((strcmp(rec->digest, digest)))
         err = TICS_EMDMATCH;
   } else
   {  err = TICS_EUNKNOWN;
   };

   test_hmac_result("string", test_num, algo, rec, digest, err);

   return( ((err)) ? TEST_ERROR : 0 );
}

/* end of source */
