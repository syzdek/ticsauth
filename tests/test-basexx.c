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
#define __TESTS_TEST_ENCODINGS_C 1
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
#include <ctype.h>

#include <ticsauth.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#undef PROGRAM_NAME
#define PROGRAM_NAME "encodings" PROGRAM_SUFFIX


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


static inline int
test_encodings_decode(
         int                           test_num,
         int                           encoding,
         test_encoding_t *             rec );


static inline int
test_encodings_encode(
         int                           test_num,
         int                           encoding,
         test_encoding_t *             rec );


static inline void
test_encodings_result(
         const char *                  title,
         int                           test_num,
         int                           encoding,
         int                           err,
         test_encoding_t *             rec );


static inline void
test_encodings_result_print(
         const char *                  field,
         const void *                  data,
         size_t                        data_len );


static inline int
test_encodings_verify(
         int                           test_num,
         int                           encoding,
         test_encoding_t *             rec );


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
   int               skipped;
   int               errors;
   int               tests;
   int               idx;
   int               rc;
   int               encoding;
   int               func;
   test_encoding_t * data;

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

   func     = TEST_FUNC;
   encoding = TEST_ENCODING;
   data     = TEST_DATA;

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {  switch(c)
      {  case -1:       /* no more arguments */
         case 0:        /* long options toggles */
            break;

         // these are not intended to be used, but rather to prevent
         // compiler warnings for unused code.
         case '0':
            func = TEST_FUNC_DEC;
            break;
         case '1':
            func = TEST_FUNC_ENC;
            break;
         case '2':
            func = TEST_FUNC_VER;
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
   {  fprintf(stderr, "%s: unknown argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   // use test data sets
   for(idx = 0; ( ((data[idx].decoded)) && ((data[idx].encoded)) ); idx++)
   {  tests++;
      switch(func)
      {  case TEST_FUNC_ENC:   rc = test_encodings_encode(tests, encoding, &data[idx]); break;
         case TEST_FUNC_DEC:   rc = test_encodings_decode(tests, encoding, &data[idx]); break;
         case TEST_FUNC_VER:   rc = test_encodings_verify(tests, encoding, &data[idx]); break;
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
      printf("    records skipped:  %3i\n", skipped);
      printf("    records passed:   %3i\n", (tests - errors - skipped));
      printf("    records failed:   %3i\n", errors);
      printf("    total digests:    %3i\n", tests);
   };

   return( ((errors)) ? 1 : 0 );
}


int
test_encodings_encode(
         int                           test_num,
         int                           encoding,
         test_encoding_t *             rec )
{
   int               err;
   ssize_t           rc;
   size_t            idx;
   char              res[1024];

   assert(rec != NULL);

   if ( (!(rec->decoded)) || (!(rec->encoded)) )
      return(TEST_SKIP);

   memset(res, 0, sizeof(res));
   if ((rc = tics_encode(encoding, rec->decoded, rec->decode_len, res, sizeof(res))) >= TICS_SUCCESS)
   {  rec->result       = res;
      rec->result_len   = (size_t)rc;
   };
   err   = (rc < TICS_SUCCESS)
         ? (int)rc
         : 0;

   if (!(err))
      if (rec->encode_len != rec->result_len)
         err = TICS_EUNKNOWN;

   for(idx = 0; ((idx < rec->result_len) && (!(err))); idx++)
      if (((const uint8_t *)rec->result)[idx] != ((const uint8_t *)rec->encoded)[idx])
         err = TICS_EUNKNOWN;

   test_encodings_result("encode", test_num, encoding, err, rec);

   return( ((err)) ? TEST_ERROR : 0 );
}


int
test_encodings_decode(
         int                           test_num,
         int                           encoding,
         test_encoding_t *             rec )
{
   int               err;
   ssize_t           rc;
   size_t            idx;
   char              res[1024];

   assert(rec != NULL);

   if ( (!(rec->decoded)) || (!(rec->encoded)) )
   {  test_encodings_result("decode", test_num, encoding, TICS_SUCCESS, NULL);
      return(TEST_SKIP);
   };

   memset(res, 0, sizeof(res));
   if ((rc = tics_decode(encoding, rec->encoded, rec->encode_len, res, sizeof(res))) >= TICS_SUCCESS)
   {  rec->result       = res;
      rec->result_len   = (size_t)rc;
   };
   err   = (rc < TICS_SUCCESS)
         ? (int)rc
         : 0;

   if (!(err))
      if (rec->decode_len != rec->result_len)
         err = TICS_EUNKNOWN;

   for(idx = 0; ((idx < rec->result_len) && (!(err))); idx++)
      if (((const uint8_t *)rec->result)[idx] != ((const uint8_t *)rec->decoded)[idx])
         err = TICS_EUNKNOWN;

   test_encodings_result("decode", test_num, encoding, err, rec);

   return( ((err)) ? TEST_ERROR : 0 );
}



void
test_encodings_result(
         const char *                  title,
         int                           test_num,
         int                           encoding,
         int                           err,
         test_encoding_t *             rec )
{
   const char *      base;

   if ( (!(verbose)) && (!(err)) )
      return;

   switch(encoding)
   {  case TICS_ENCODE_BASE16:      base = "base16"; break;
      case TICS_ENCODE_BASE32:      base = "base32"; break;
      case TICS_ENCODE_BASE32HEX:   base = "base32hex"; break;
      case TICS_ENCODE_BASE64:      base = "base64"; break;
      default:                      base = "unknown"; break;
   };

   printf("%2i. %s %s test\n", test_num, base, title);
   if (!(rec))
   {  printf("    skipping ...\n");
      printf("\n");
      return;
   };

   if ((rec->decoded))
      test_encodings_result_print("Decoded:",   rec->decoded, rec->decode_len);
   if ((rec->encoded))
      test_encodings_result_print("Encoded:",   rec->encoded, rec->encode_len);
   if ((rec->result))
      test_encodings_result_print("Result:",    rec->result, rec->result_len);

  if ( (verbose > 1) || ((err)) )
  {   if ((rec->decoded))
         printf("    Decoded Len: %zu\n", rec->decode_len);
      if ((rec->encoded))
         printf("    Encoded Len: %zu\n", rec->encode_len);
      if ((rec->result))
         printf("    Result Len:  %zu\n", rec->result_len);
   };
   if ((err))
      printf("    Error:       %s (%i)\n", tics_strerror(err), err);

   printf("\n");

   return;
}


void
test_encodings_result_print(
         const char *                  field,
         const void *                  data,
         size_t                        data_len )
{
   size_t            bin;
   size_t            ascii;
   size_t            pad;
   const char *      str;
   const uint8_t *   byt;

   str = data;
   byt = data;

   printf("    %-12s", field);
   for(bin = 0, ascii = 0; (bin < data_len); bin++)
   {  if ( ((bin % 16) == 0) && ((bin)) )
      {  printf("   ");
         for(; (ascii < bin); ascii++)
         {  if ((isprint(str[ascii])))
               printf("%c", str[ascii]);
            else
               printf(".");
         };
         printf("\n    %12s", " ");
      };
      printf(" %02x", byt[bin]);
   };
   for(pad = bin; ((pad % 16)); pad++)
       printf("   ");
   printf("   ");
   for(; (ascii < bin); ascii++)
   {  if ((isprint(str[ascii])))
         printf("%c", str[ascii]);
      else
         printf(".");
   };
   printf("\n");

   return;
}


int
test_encodings_verify(
         int                           test_num,
         int                           encoding,
         test_encoding_t *             rec )
{
   ssize_t     rc;
   int         err;

   assert(rec != NULL);

   if (!(rec->encoded))
      return(TEST_SKIP);

   rc    = tics_encoding_verify(encoding, rec->encoded, rec->encode_len);
   err   = (rc < TICS_SUCCESS)
         ? (int)rc
         : TICS_SUCCESS;

   test_encodings_result("verify encoding", test_num, encoding, err, rec);

   return( ((err)) ? TEST_ERROR : 0 );
}



/* end of source */
