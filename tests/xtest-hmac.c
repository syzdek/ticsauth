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
#define __TESTS_XTEST_HMAC_C 1

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
#   define PROGRAM_NAME "xtest-hmac"
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
#define TEST_KEY        "Reading the documentation"
#define TEST_KEY_LEN    25


#if (TEST_HASH == TICS_HASH_MD5)
#  define TEST_MD_LEN         TICS_MD_SIZE_MD5
#  define TEST_RESULT         (const uint8_t []){0xe5, 0xd2, 0x4d, 0xa6, 0xb8, 0xf0, 0x20, 0x6c, 0xa1, 0x87, 0xd8, 0xa4, 0x0f, 0x0c, 0x74, 0x18}
#  define TEST_RESULT5        (const uint8_t []){0x12, 0x8b, 0x3d, 0xd3, 0x49, 0x56, 0x89, 0xc7, 0x3d, 0x29, 0xce, 0xfa, 0x58, 0x36, 0x4c, 0x87}
#  define TEST_RESULT10       (const uint8_t []){0xef, 0x6d, 0xd6, 0x5b, 0x6a, 0x7c, 0xb3, 0x61, 0x55, 0xc2, 0x39, 0x88, 0x37, 0x02, 0x93, 0xd6}
#  define TEST_RESULT_STR     "e5d24da6b8f0206ca187d8a40f0c7418"
#  define TEST_RESULT_STR5    "128b3dd3495689c73d29cefa58364c87"
#  define TEST_RESULT_STR10   "ef6dd65b6a7cb36155c23988370293d6"
#elif (TEST_HASH == TICS_HASH_SHA1)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA1
#  define TEST_RESULT         (const uint8_t []){0x7d, 0xaa, 0x9c, 0x92, 0xbf, 0xb4, 0x6d, 0xf8, 0x77, 0xd6, 0xff, 0x36, 0xde, 0x52, 0x3a, 0x81, 0x6b, 0x07, 0xb0, 0x11}
#  define TEST_RESULT5        (const uint8_t []){0xf1, 0xba, 0x5c, 0xcc, 0xff, 0x3d, 0xdc, 0x7d, 0xe4, 0x07, 0x75, 0x26, 0x5d, 0x4d, 0x42, 0x6c, 0x50, 0x7b, 0x1e, 0xe5}
#  define TEST_RESULT10       (const uint8_t []){0x3f, 0x31, 0xd6, 0xf1, 0x6c, 0x54, 0x12, 0x46, 0x20, 0x29, 0xef, 0xab, 0x4a, 0xfb, 0x8a, 0x4a, 0x12, 0x60, 0xac, 0xa9}
#  define TEST_RESULT_STR     "7daa9c92bfb46df877d6ff36de523a816b07b011"
#  define TEST_RESULT_STR5    "f1ba5cccff3ddc7de40775265d4d426c507b1ee5"
#  define TEST_RESULT_STR10   "3f31d6f16c5412462029efab4afb8a4a1260aca9"
#elif (TEST_HASH == TICS_HASH_SHA224)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA224
#  define TEST_RESULT         (const uint8_t []){0x3d, 0x32, 0x54, 0x81, 0x2c, 0x65, 0xcd, 0x14, 0x2e, 0x2a, 0xf0, 0x9a, 0xce, 0x2c, 0x72, 0xb0, 0xe4, 0xda, 0x04, 0xd7, 0xa7, 0x6d, 0x71, 0xd9, 0x88, 0x07, 0x75, 0xee}
#  define TEST_RESULT5        (const uint8_t []){0x52, 0xee, 0x8d, 0x55, 0xb4, 0xc6, 0x19, 0xdb, 0xb6, 0x0c, 0xb5, 0xca, 0x97, 0x4a, 0x55, 0x48, 0x65, 0xc1, 0x52, 0x31, 0xa1, 0x63, 0x8a, 0x2c, 0x1c, 0xbc, 0x96, 0xd2}
#  define TEST_RESULT10       (const uint8_t []){0xec, 0x1c, 0x53, 0x19, 0x17, 0xf3, 0x61, 0x0e, 0x16, 0x27, 0xfd, 0x71, 0xb5, 0x16, 0x21, 0xb8, 0x86, 0x12, 0xb0, 0x24, 0x6a, 0x7e, 0xce, 0xaf, 0x40, 0xba, 0x56, 0xd7}
#  define TEST_RESULT_STR     "3d3254812c65cd142e2af09ace2c72b0e4da04d7a76d71d9880775ee"
#  define TEST_RESULT_STR5    "52ee8d55b4c619dbb60cb5ca974a554865c15231a1638a2c1cbc96d2"
#  define TEST_RESULT_STR10   "ec1c531917f3610e1627fd71b51621b88612b0246a7eceaf40ba56d7"
#elif (TEST_HASH == TICS_HASH_SHA256)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA256
#  define TEST_RESULT         (const uint8_t []){0x9f, 0xd9, 0x57, 0xd0, 0x6f, 0x72, 0x29, 0x39, 0x7d, 0xa5, 0x0f, 0xe0, 0x8c, 0x43, 0x47, 0x5a, 0x52, 0xf3, 0xe8, 0xbd, 0x9f, 0xe2, 0x0c, 0xee, 0xfb, 0x5d, 0x42, 0xd2, 0x06, 0x3d, 0x7a, 0x47}
#  define TEST_RESULT5        (const uint8_t []){0x5e, 0xdd, 0x25, 0x97, 0x50, 0x60, 0x2a, 0x38, 0xe8, 0x33, 0x2a, 0x67, 0xd2, 0x84, 0xa6, 0x09, 0x5f, 0x0d, 0xe9, 0x55, 0x61, 0x8f, 0x7d, 0x6f, 0x65, 0x45, 0x6b, 0x38, 0xb8, 0x12, 0x67, 0x45}
#  define TEST_RESULT10       (const uint8_t []){0x0a, 0xac, 0xfd, 0x04, 0x37, 0xb6, 0x83, 0x4d, 0xc8, 0x30, 0x8b, 0x23, 0x33, 0x2e, 0x3c, 0x9f, 0xf5, 0x0a, 0xaf, 0x0d, 0x5e, 0xd3, 0x38, 0xf3, 0x97, 0x64, 0xdb, 0x53, 0xa8, 0xc6, 0xa9, 0x40}
#  define TEST_RESULT_STR     "9fd957d06f7229397da50fe08c43475a52f3e8bd9fe20ceefb5d42d2063d7a47"
#  define TEST_RESULT_STR5    "5edd259750602a38e8332a67d284a6095f0de955618f7d6f65456b38b8126745"
#  define TEST_RESULT_STR10   "0aacfd0437b6834dc8308b23332e3c9ff50aaf0d5ed338f39764db53a8c6a940"
#elif (TEST_HASH == TICS_HASH_SHA384)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA384
#  define TEST_RESULT         (const uint8_t []){0x0f, 0x46, 0xa6, 0x28, 0x89, 0x6d, 0x15, 0x00, 0xfe, 0x28, 0x98, 0xa3, 0xa1, 0x30, 0x1e, 0x70, 0x6c, 0x65, 0xe3, 0x94, 0x62, 0x3b, 0xa7, 0x25, 0xf3, 0xc4, 0x1f, 0x5d, 0x0a, 0x2a, 0xfa, 0x2e, 0x68, 0x16, 0xbb, 0x82, 0x55, 0xcd, 0x6a, 0xa0, 0x71, 0xad, 0xf8, 0x2c, 0x10, 0x91, 0xd3, 0xed}
#  define TEST_RESULT5        (const uint8_t []){0x09, 0x0a, 0xab, 0xba, 0x69, 0x64, 0xd5, 0xa9, 0x46, 0xf9, 0x16, 0xed, 0xd0, 0x3c, 0xc7, 0xad, 0x8a, 0x8e, 0x42, 0xb5, 0x3c, 0x8b, 0x5c, 0x5d, 0xf8, 0xde, 0x94, 0x48, 0x1f, 0x4f, 0x2c, 0xc8, 0x96, 0xb4, 0xaa, 0x86, 0xaf, 0xce, 0xd7, 0x0c, 0x8f, 0x2a, 0xe6, 0xaa, 0x82, 0xa3, 0xaa, 0xc9}
#  define TEST_RESULT10       (const uint8_t []){0x30, 0x0a, 0x25, 0x3a, 0x15, 0xe1, 0x06, 0xf1, 0xa4, 0x10, 0xe2, 0x63, 0x47, 0x80, 0xfd, 0x18, 0xe1, 0x40, 0x08, 0x59, 0xbd, 0xcb, 0x46, 0xfb, 0x99, 0xac, 0xa1, 0x9a, 0x37, 0xf0, 0x16, 0x4a, 0x9e, 0xb0, 0x38, 0x51, 0xf7, 0x11, 0x7b, 0x2b, 0xdf, 0xf5, 0x5e, 0xa2, 0x28, 0x7e, 0xda, 0x29}
#  define TEST_RESULT_STR     "0f46a628896d1500fe2898a3a1301e706c65e394623ba725f3c41f5d0a2afa2e6816bb8255cd6aa071adf82c1091d3ed"
#  define TEST_RESULT_STR5    "090aabba6964d5a946f916edd03cc7ad8a8e42b53c8b5c5df8de94481f4f2cc896b4aa86afced70c8f2ae6aa82a3aac9"
#  define TEST_RESULT_STR10   "300a253a15e106f1a410e2634780fd18e1400859bdcb46fb99aca19a37f0164a9eb03851f7117b2bdff55ea2287eda29"
#elif (TEST_HASH == TICS_HASH_SHA512)
#  define TEST_MD_LEN         TICS_MD_SIZE_SHA512
#  define TEST_RESULT         (const uint8_t []){0x81, 0x87, 0x3d, 0xe4, 0x1b, 0xfd, 0x6a, 0x77, 0xe2, 0x1f, 0xe9, 0xc8, 0xc7, 0x46, 0xec, 0x95, 0x96, 0xfb, 0xac, 0x11, 0x9c, 0x06, 0x35, 0x6f, 0x60, 0x74, 0xd4, 0x44, 0x43, 0xf2, 0xd2, 0xa7, 0x9b, 0x7a, 0x15, 0x55, 0xc8, 0xc5, 0xd2, 0x3d, 0xe4, 0xfd, 0xb3, 0x84, 0xde, 0x7b, 0x97, 0x9f, 0x76, 0xd2, 0x31, 0xe9, 0x80, 0x96, 0x95, 0x26, 0xec, 0xcb, 0xd3, 0x83, 0x29, 0xf8, 0x08, 0x8b}
#  define TEST_RESULT5        (const uint8_t []){0x6f, 0x0a, 0x65, 0x6f, 0x93, 0x52, 0xd1, 0xa5, 0xab, 0x91, 0x37, 0x05, 0x89, 0x53, 0x0f, 0xde, 0xd3, 0x7e, 0x33, 0xe2, 0x03, 0x00, 0xf7, 0x97, 0x79, 0xfc, 0x36, 0x59, 0x96, 0x7c, 0xdd, 0xfa, 0xca, 0xd8, 0xab, 0x26, 0x81, 0x16, 0xd8, 0xbe, 0x67, 0x40, 0x3b, 0x88, 0xfc, 0x10, 0xdb, 0xa8, 0xb0, 0x0b, 0x40, 0xc4, 0x87, 0xbf, 0x0b, 0x75, 0x68, 0xad, 0x19, 0x34, 0xa8, 0x8d, 0x5b, 0x12}
#  define TEST_RESULT10       (const uint8_t []){0x6f, 0x6b, 0xfa, 0xbe, 0xf7, 0x1f, 0x99, 0xb5, 0xc5, 0x32, 0xa9, 0x51, 0x40, 0xc5, 0x31, 0x18, 0x72, 0x5d, 0x8b, 0xd8, 0xf9, 0xef, 0x53, 0xc7, 0x12, 0xbc, 0xd3, 0x49, 0x12, 0x39, 0xd2, 0xf1, 0x69, 0x26, 0x4e, 0xdd, 0xc5, 0x98, 0x8c, 0x8d, 0xfa, 0x32, 0xf5, 0x78, 0xa0, 0x34, 0x10, 0x2e, 0x35, 0x11, 0xa0, 0x34, 0x45, 0x1e, 0x58, 0x56, 0x4e, 0xb5, 0xd6, 0xf9, 0xbe, 0x15, 0x67, 0x8c}
#  define TEST_RESULT_STR     "81873de41bfd6a77e21fe9c8c746ec9596fbac119c06356f6074d44443f2d2a79b7a1555c8c5d23de4fdb384de7b979f76d231e980969526eccbd38329f8088b"
#  define TEST_RESULT_STR5    "6f0a656f9352d1a5ab91370589530fded37e33e20300f79779fc3659967cddfacad8ab268116d8be67403b88fc10dba8b00b40c487bf0b7568ad1934a88d5b12"
#  define TEST_RESULT_STR10   "6f6bfabef71f99b5c532a95140c53118725d8bd8f9ef53c712bcd3491239d2f169264eddc5988c8dfa32f578a034102e3511a034451e58564eb5d6f9be15678c"
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
   tics_hmac_t *     ctx;
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

   if ((rc = tics_hmac_init(&ctx, TEST_HASH, TEST_KEY, TEST_KEY_LEN)) != TICS_SUCCESS)
   {  fprintf(stderr, "%s: tics_hash_init(): %s\n", PROGRAM_NAME, tics_strerror(rc));
      return(1);
   };

   for(count = 0; (count < 10); count++)
   {  if ((verbose))
         printf("   starting round %i\n", count);
      if ((rc = tics_hmac_update(ctx, TEST_DATA, TEST_DATA_LEN)) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: tics_hash_update(): %s\n", PROGRAM_NAME, tics_strerror(rc));
         tics_hmac_free(ctx);
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
         if ((rc = tics_hmac_result(ctx, md, TEST_MD_LEN)) != TICS_SUCCESS)
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result(): %s\n", PROGRAM_NAME, count, pad_vals[pass], tics_strerror(rc));
            tics_hmac_free(ctx);
            return(1);
         };
         if ((memcmp(md, expected, TEST_MD_LEN)))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result() message digest does not match\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hmac_free(ctx);
            return(1);
         };
         if ((memcmp(&md[TEST_MD_LEN], pad, TEST_MD_LEN)))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result() wrote data past buffer\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hmac_free(ctx);
            return(1);
         };

         // manually test string result
         memset(md_str, pad_vals[pass], sizeof(md_str));
         if ((rc = (int)tics_hmac_result_str(ctx, md_str, ((TEST_MD_LEN*2)+1))) < TICS_SUCCESS)
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result_str(): %s\n", PROGRAM_NAME, count, pad_vals[pass], tics_strerror(rc));
            tics_hmac_free(ctx);
            return(1);
         };
         if ((strncmp(md_str, expected_str, TEST_MD_LEN)))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result_str() message digest does not match\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hmac_free(ctx);
            return(1);
         };
         if ((memcmp(&md_str[TEST_MD_LEN*2]+1, pad, (TEST_MD_LEN-1))))
         {  fprintf(stderr, "%s: round %i: padding 0x%02x: tics_hash_result_str() wrote data past buffer\n", PROGRAM_NAME, count, pad_vals[pass]);
            tics_hmac_free(ctx);
            return(1);
         };
      };

/*
      // use function to test binary result
      if ((rc = tics_hmac_verify(ctx, expected, TEST_MD_LEN)) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: round %i: tics_hash_verify(): %s\n", PROGRAM_NAME, count, tics_strerror(rc));
         tics_hmac_free(ctx);
         return(1);
      };

      // use function to test string result
      if ((rc = tics_hmac_verify_str(ctx, expected_str)) != TICS_SUCCESS)
      {  fprintf(stderr, "%s: round %i: tics_hash_verify_str(): %s\n", PROGRAM_NAME, count, tics_strerror(rc));
         tics_hmac_free(ctx);
         return(1);
      };
*/
   };

   tics_hmac_free(ctx);

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

      if ((ptr = tics_hmac(TEST_HASH, TEST_KEY, TEST_KEY_LEN, TEST_DATA, TEST_DATA_LEN, md, TEST_MD_LEN)) == NULL)
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
