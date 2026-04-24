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
#define __TESTS_XTEST_HASH_C 1

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

#ifndef PROGRAM_NAME
#   define PROGRAM_NAME "xtest-hash"
#endif
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


#ifndef TEST_HASH
#  define TEST_HASH TICS_HASH_SHA1
#endif


#define TEST_DATA       "TICS Implements Complete Standards"
#define TEST_DATA_LEN   34


#if (TEST_HASH == TICS_HASH_MD5)
#  define TEST_MD_LEN         TICS_MD_SIZE_MD5
#  define TEST_RESULT         (const uint8_t []){0x3d, 0x1a, 0xae, 0x96, 0x66, 0x14, 0xa4, 0x32, 0x07, 0xc3, 0x66, 0xa6, 0x81, 0x94, 0x97, 0x39}
#  define TEST_RESULT5        (const uint8_t []){0x20, 0x33, 0x72, 0xda, 0x9b, 0x39, 0xce, 0xc4, 0x9a, 0x9b, 0xbc, 0x4c, 0x76, 0xe5, 0xcb, 0x1b}
#  define TEST_RESULT10       (const uint8_t []){0xde, 0x0a, 0xfe, 0x2c, 0xf4, 0x1b, 0x69, 0x88, 0x5f, 0x9c, 0x5b, 0x93, 0x33, 0x8d, 0x02, 0x3d}
#  define TEST_RESULT_STR     "3d1aae966614a43207c366a681949739"
#  define TEST_RESULT_STR5    "203372da9b39cec49a9bbc4c76e5cb1b"
#  define TEST_RESULT_STR10   "de0afe2cf41b69885f9c5b93338d023d"
#elif (TEST_HASH == TICS_HASH_SHA1)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA1
#  define TEST_RESULT         (const uint8_t []){0xc3, 0xe7, 0x20, 0xe6, 0x42, 0x02, 0x33, 0xa2, 0xd0, 0xe3, 0x76, 0x0f, 0xbf, 0x7a, 0xda, 0x60, 0xf9, 0x21, 0x5c, 0x65}
#  define TEST_RESULT5        (const uint8_t []){0x5a, 0x2e, 0x07, 0x7a, 0x6c, 0x8d, 0x68, 0x15, 0x22, 0x14, 0xd6, 0x12, 0xdf, 0x97, 0x5b, 0xc6, 0xf9, 0x27, 0x0a, 0xe5}
#  define TEST_RESULT10       (const uint8_t []){0xcd, 0x29, 0xa5, 0xba, 0x97, 0x0e, 0x99, 0xf4, 0x89, 0xc5, 0x13, 0x24, 0x3f, 0x12, 0xb7, 0xcb, 0x47, 0xd3, 0x5a, 0xde}
#  define TEST_RESULT_STR     "c3e720e6420233a2d0e3760fbf7ada60f9215c65"
#  define TEST_RESULT_STR5    "5a2e077a6c8d68152214d612df975bc6f9270ae5"
#  define TEST_RESULT_STR10   "cd29a5ba970e99f489c513243f12b7cb47d35ade"
#elif (TEST_HASH == TICS_HASH_SHA224)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA224
#  define TEST_RESULT         (const uint8_t []){0xa7, 0xfb, 0x26, 0x5d, 0xf6, 0xb7, 0x1d, 0x88, 0x21, 0x99, 0x54, 0x45, 0x56, 0xb9, 0xc8, 0x48, 0x12, 0x30, 0xce, 0x6e, 0x6b, 0xa7, 0x84, 0x85, 0xb7, 0xdd, 0xe7, 0x02}
#  define TEST_RESULT5        (const uint8_t []){0xce, 0xd6, 0x20, 0x9e, 0x5c, 0x5b, 0x33, 0x1d, 0xe5, 0xb6, 0x87, 0x68, 0xd5, 0x9e, 0x9a, 0x02, 0xe8, 0xd6, 0x1b, 0x92, 0x58, 0x1e, 0x1e, 0x19, 0x53, 0xf6, 0xd8, 0xdd}
#  define TEST_RESULT10       (const uint8_t []){0xe6, 0x89, 0xca, 0x5e, 0x4f, 0xbe, 0x75, 0x4d, 0x3c, 0xe6, 0xa3, 0x9c, 0x2d, 0x7c, 0x1e, 0xf0, 0xb8, 0xaa, 0x44, 0xc9, 0xe2, 0x91, 0x71, 0xf1, 0xb5, 0x94, 0x86, 0x90}
#  define TEST_RESULT_STR     "a7fb265df6b71d882199544556b9c8481230ce6e6ba78485b7dde702"
#  define TEST_RESULT_STR5    "ced6209e5c5b331de5b68768d59e9a02e8d61b92581e1e1953f6d8dd"
#  define TEST_RESULT_STR10   "e689ca5e4fbe754d3ce6a39c2d7c1ef0b8aa44c9e29171f1b5948690"
#elif (TEST_HASH == TICS_HASH_SHA256)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA256
#  define TEST_RESULT         (const uint8_t []){0x86, 0x8c, 0x3a, 0xfe, 0x01, 0x1d, 0x94, 0xb2, 0xd2, 0x31, 0xf4, 0xce, 0x7a, 0x37, 0xa7, 0xf3, 0x1f, 0x79, 0x5c, 0x57, 0xb7, 0x2a, 0xf7, 0x4b, 0x6c, 0x49, 0x6e, 0x95, 0x0f, 0x28, 0x66, 0x64}
#  define TEST_RESULT5        (const uint8_t []){0x01, 0x15, 0x83, 0xae, 0xb6, 0xdb, 0x66, 0x40, 0x35, 0x4f, 0x24, 0x35, 0xf9, 0x53, 0xc0, 0x0e, 0xa4, 0x0f, 0x9a, 0x55, 0x3e, 0x2d, 0x8b, 0x14, 0xb1, 0x9c, 0x89, 0x8c, 0xbf, 0x82, 0x28, 0xab}
#  define TEST_RESULT10       (const uint8_t []){0x58, 0x93, 0xbe, 0x76, 0xee, 0x7e, 0x0b, 0xc2, 0xbd, 0x04, 0x1e, 0x2a, 0xb1, 0x3f, 0x39, 0xa5, 0xe7, 0x95, 0x91, 0x8d, 0xc6, 0xe5, 0xcc, 0xf1, 0x91, 0x56, 0xff, 0x55, 0x11, 0xbb, 0x2c, 0x34}
#  define TEST_RESULT_STR     "868c3afe011d94b2d231f4ce7a37a7f31f795c57b72af74b6c496e950f286664"
#  define TEST_RESULT_STR5    "011583aeb6db6640354f2435f953c00ea40f9a553e2d8b14b19c898cbf8228ab"
#  define TEST_RESULT_STR10   "5893be76ee7e0bc2bd041e2ab13f39a5e795918dc6e5ccf19156ff5511bb2c34"
#elif (TEST_HASH == TICS_HASH_SHA384)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA384
#  define TEST_RESULT         (const uint8_t []){0x83, 0x71, 0xdc, 0x74, 0xda, 0x8c, 0x10, 0x75, 0xe8, 0x4e, 0xd2, 0xda, 0xe0, 0x53, 0xf0, 0x60, 0x17, 0xd1, 0x34, 0xe5, 0x81, 0x74, 0xed, 0x97, 0x6a, 0xa5, 0x12, 0x77, 0xd0, 0x03, 0xd7, 0x00, 0x69, 0x11, 0x3b, 0x1e, 0xf5, 0xd0, 0x06, 0xec, 0x92, 0x11, 0xb5, 0xdc, 0x29, 0xec, 0x35, 0xf9}
#  define TEST_RESULT5        (const uint8_t []){0x26, 0x42, 0xe4, 0xbf, 0x99, 0xd6, 0x5e, 0x9e, 0x15, 0x6f, 0x05, 0xbe, 0x46, 0x7f, 0x4b, 0x1f, 0xfd, 0xac, 0x0a, 0x3f, 0xe1, 0x2b, 0x5d, 0xde, 0x0e, 0xb9, 0x3b, 0x1f, 0xe4, 0x66, 0x3c, 0x07, 0x38, 0xfe, 0x3c, 0x96, 0x5f, 0x3d, 0x10, 0xef, 0xe7, 0x2f, 0xc3, 0xb9, 0x39, 0xf3, 0x28, 0x7c}
#  define TEST_RESULT10       (const uint8_t []){0x36, 0xf5, 0x50, 0x69, 0xa0, 0x67, 0x3f, 0xf3, 0x2e, 0xd6, 0xd6, 0xf9, 0x11, 0x37, 0x42, 0xf4, 0xd1, 0xae, 0x8b, 0x23, 0xa0, 0x3d, 0xcb, 0x7d, 0xe7, 0xe4, 0x66, 0x43, 0x10, 0x74, 0x05, 0x54, 0xef, 0xa1, 0x0d, 0x1c, 0x22, 0xe3, 0x03, 0x22, 0xdf, 0x7e, 0x36, 0x83, 0x14, 0x40, 0x7d, 0xca}
#  define TEST_RESULT_STR     "8371dc74da8c1075e84ed2dae053f06017d134e58174ed976aa51277d003d70069113b1ef5d006ec9211b5dc29ec35f9"
#  define TEST_RESULT_STR5    "2642e4bf99d65e9e156f05be467f4b1ffdac0a3fe12b5dde0eb93b1fe4663c0738fe3c965f3d10efe72fc3b939f3287c"
#  define TEST_RESULT_STR10   "36f55069a0673ff32ed6d6f9113742f4d1ae8b23a03dcb7de7e4664310740554efa10d1c22e30322df7e368314407dca"
#elif (TEST_HASH == TICS_HASH_SHA512)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA512
#  define TEST_RESULT         (const uint8_t []){0xd5, 0x56, 0xc0, 0x2b, 0x31, 0x4d, 0x57, 0x11, 0x5d, 0x56, 0xfc, 0x5e, 0x78, 0xb2, 0x70, 0x2b, 0x29, 0x4c, 0x78, 0x45, 0xe4, 0x22, 0x0d, 0x44, 0x0a, 0x58, 0xf6, 0x0a, 0xf9, 0xd2, 0x24, 0x35, 0xdc, 0x91, 0xbf, 0xd0, 0xa4, 0xae, 0x8e, 0x14, 0x8f, 0xa8, 0x48, 0xbd, 0x27, 0xaa, 0x25, 0xf9, 0x07, 0xec, 0x2e, 0x52, 0xe8, 0x2c, 0x87, 0xe3, 0x10, 0xdb, 0xcf, 0xda, 0xfa, 0xe8, 0xed, 0x7e}
#  define TEST_RESULT5        (const uint8_t []){0x14, 0x46, 0xd1, 0xfa, 0xb5, 0x37, 0x14, 0x74, 0x5c, 0x58, 0x6a, 0x7b, 0x92, 0xe1, 0xc9, 0x2e, 0xd4, 0x54, 0xe0, 0x60, 0x20, 0x38, 0xf7, 0x4f, 0x65, 0x68, 0x87, 0x7d, 0x7c, 0x01, 0x9d, 0x13, 0x91, 0x08, 0x23, 0x7d, 0x35, 0x74, 0x68, 0xab, 0x9f, 0x15, 0xb8, 0xc8, 0x18, 0xa8, 0x64, 0x84, 0x10, 0x88, 0xfe, 0x3e, 0x55, 0xa0, 0x45, 0x4f, 0xf1, 0xab, 0x00, 0x01, 0x92, 0xd5, 0xfc, 0x9f}
#  define TEST_RESULT10       (const uint8_t []){0xec, 0x16, 0x84, 0x71, 0xbe, 0xa9, 0x5c, 0x80, 0x0b, 0x3a, 0xdd, 0x8a, 0xd5, 0x97, 0xa7, 0xef, 0x7d, 0xfd, 0x12, 0x4b, 0xad, 0x6a, 0xdc, 0xf8, 0xc7, 0x13, 0xd2, 0x0d, 0xf8, 0x03, 0x33, 0xbf, 0xd0, 0x0c, 0x5e, 0x30, 0xc6, 0x3c, 0xe7, 0xc2, 0x2d, 0x6b, 0xb1, 0xca, 0x06, 0x97, 0xa2, 0x5c, 0x6b, 0x8c, 0x0d, 0x74, 0x99, 0x8b, 0xe9, 0xce, 0x39, 0x6d, 0x75, 0x0e, 0x75, 0xdc, 0x93, 0xea}
#  define TEST_RESULT_STR     "d556c02b314d57115d56fc5e78b2702b294c7845e4220d440a58f60af9d22435dc91bfd0a4ae8e148fa848bd27aa25f907ec2e52e82c87e310dbcfdafae8ed7e"
#  define TEST_RESULT_STR5    "1446d1fab53714745c586a7b92e1c92ed454e0602038f74f6568877d7c019d139108237d357468ab9f15b8c818a864841088fe3e55a0454ff1ab000192d5fc9f"
#  define TEST_RESULT_STR10   "ec168471bea95c800b3add8ad597a7ef7dfd124bad6adcf8c713d20df80333bfd00c5e30c63ce7c22d6bb1ca0697a25c6b8c0d74998be9ce396d750e75dc93ea"
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


static inline int
test_contexts(
         const char *                  algo_str );


static inline int
test_convenience(
         const char *                  algo_str );


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
   const char *      algo_str;

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

#ifdef XTEST_ALGORITHM
   if ((algo_str = tics_algo2str(-1)) == NULL)
#else
   if ((algo_str = tics_algo2str(TEST_HASH)) == NULL)
#endif
   {  fprintf(stderr, "%s: tics_algo2str(): unknown algorithm\n", PROGRAM_NAME);
      return(1);
   };

   if ((test_contexts(algo_str)))
      return(1);

   if ((test_convenience(algo_str)))
      return(1);

   return(0);
}


int
test_contexts(
         const char *                  algo_str )
{
   int               rc;
   int               count;
   int               pass;
   tics_hash_t *     ctx;
   const uint8_t *   expected;
   const char *      expected_str;
   uint8_t           md[TEST_MD_LEN*4];
   char              md_str[TEST_MD_LEN*4];
   uint8_t           pad[TEST_MD_LEN*4];
   const uint8_t *   pad_vals;

   pad_vals = (const uint8_t []){ 0x55, 0xaa, 0x00 };

   memset(pad,   0, sizeof(pad));

   if (!(quiet))
      printf("testing %s context functions ...\n", algo_str);

   if ((rc = tics_hash_init(&ctx, TEST_HASH)) != TICS_SUCCESS)
   {  fprintf(stderr, "%s: tics_hash_init(): %s\n", PROGRAM_NAME, tics_strerror(rc));
      return(1);
   };

   for(count = 0; (count < 10); count++)
   {  if ((verbose))
         printf("   starting round %i\n", count);
      if ((rc = tics_hash_update(ctx, TEST_DATA, TEST_DATA_LEN)) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: tics_hash_update(): %s\n", PROGRAM_NAME, tics_strerror(rc));
         tics_hash_free(ctx);
         return(1);
      };

      switch(count+1)
      {  case  1:
            expected       = TEST_RESULT;
            expected_str   = TEST_RESULT_STR;
            break;

         case  5:
            expected       = TEST_RESULT5;
            expected_str   = TEST_RESULT_STR5;
            break;

         case 10:
            expected       = TEST_RESULT10;
            expected_str   = TEST_RESULT_STR10;
            break;

         default:
            if (verbose > 1)
               printf("      skipping result ...\n");
            continue;
      };

      // use differnet paddings to verify there were no overruns
      for(pass = 0; (pass < 2); pass++)
      {  memset(pad, pad_vals[pass], sizeof(pad));
         if (verbose > 1)
            printf("      testing results with 0x%02x pad ...\n", pad_vals[pass]);

         // manually test binary result
         memset(md,  pad_vals[pass], sizeof(md));
         if ((rc = tics_hash_result(ctx, md, TEST_MD_LEN)) != TICS_SUCCESS)
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result(): %s\n", PROGRAM_NAME, count, pad_vals[pass], tics_strerror(rc));
            tics_hash_free(ctx);
            return(1);
         };
         if ((memcmp(md, expected, TEST_MD_LEN)))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result() message digest does not match\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hash_free(ctx);
            return(1);
         };
         if ((memcmp(&md[TEST_MD_LEN], pad, TEST_MD_LEN)))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result() wrote data past buffer\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hash_free(ctx);
            return(1);
         };

         // manually test string result
         memset(md_str, pad_vals[pass], sizeof(md_str));
         if ((rc = (int)tics_hash_result_str(ctx, md_str, ((TEST_MD_LEN*2)+1))) < TICS_SUCCESS)
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result_str(): %s\n", PROGRAM_NAME, count, pad_vals[pass], tics_strerror(rc));
            tics_hash_free(ctx);
            return(1);
         };
         if ((strncmp(md_str, expected_str, TEST_MD_LEN)))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result_str() message digest does not match\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hash_free(ctx);
            return(1);
         };
         if ((memcmp(&md_str[TEST_MD_LEN*2]+1, pad, (TEST_MD_LEN-1))))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result_str() wrote data past buffer\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hash_free(ctx);
            return(1);
         };
      };

      // use function to test binary result
      if ((rc = tics_hash_verify(ctx, expected, TEST_MD_LEN)) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: round %i: tics_hash_verify(): %s\n", PROGRAM_NAME, count, tics_strerror(rc));
         tics_hash_free(ctx);
         return(1);
      };

      // use function to test string result
      if ((rc = tics_hash_verify_str(ctx, expected_str)) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: round %i: tics_hash_verify_str(): %s\n", PROGRAM_NAME, count, tics_strerror(rc));
         tics_hash_free(ctx);
         return(1);
      };
   };

   tics_hash_free(ctx);

   return(0);
}


int
test_convenience(
         const char *                  algo_str )
{
   int               pass;
   const char *      ptr;
   uint8_t           md[TEST_MD_LEN*4];
   uint8_t           pad[TEST_MD_LEN*4];
   const uint8_t *   pad_vals;

   pad_vals = (const uint8_t []){ 0x55, 0xaa, 0x00 };

   if (!(quiet))
      printf("testing %s convenience functions ...\n", algo_str);

   // use differnet paddings to verify there were no overruns
   for(pass = 0; (pass < 2); pass++)
   {  memset(pad, pad_vals[pass], sizeof(pad));
      memset(md,  pad_vals[pass], sizeof(md));
      if (verbose > 1)
         printf("   testing results with 0x%02x pad ...\n", pad_vals[pass]);

      if ((ptr = tics_hash(TEST_HASH, TEST_DATA, TEST_DATA_LEN, md, TEST_MD_LEN)) == NULL)
      {  fprintf(stderr, "%s: tics_hash(): unknown error\n", PROGRAM_NAME);
         return(1);
      };
      if ((memcmp(md, TEST_RESULT, TEST_MD_LEN)))
      {  fprintf(stderr, "%s: tics_hash_result() message digest does not match\n", PROGRAM_NAME);
         return(1);
      };
      if ((memcmp(&md[TEST_MD_LEN], pad, TEST_MD_LEN)))
      {  fprintf(stderr, "%s: tics_hash_result() wrote data past buffer\n", PROGRAM_NAME);
         return(1);
      };
   };

   return(0);
}


/* end of source */
