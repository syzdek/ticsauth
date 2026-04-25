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
#define __TESTS_XTEST_BASEXX_C 1

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
#   define PROGRAM_NAME "xtest-basexx"
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


#undef TEST_BUFF_LEN
#define TEST_BUFF_LEN      512


#ifndef TEST_ENCODE
#  define TEST_ENCODE TICS_ENCODE_BASE32
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _test_data_set test_data_t;
struct _test_data_set
{  const char *            encoded;
   const char *            decoded;
   size_t                  encoded_len;
   size_t                  decoded_est;
   size_t                  decoded_len;
   size_t                  __pad_size;
};


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
test_convenience(
         const char *                  encode_str );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

int verbose    = 0;
int quiet      = 0;


test_data_t test_data[] =
{  {  .decoded       = "TICS Implements Complete Standards",
      .decoded_len   = 34,
#if (TEST_ENCODE == TICS_ENCODE_BASE16)
      .encoded       = "5449435320496d706c656d656e747320436f6d706c657465205374616e6461726473",
      .encoded_len   = 68,
      .decoded_est   = 34,
#elif (TEST_ENCODE == TICS_ENCODE_BASE32)
      .encoded       = "KREUGUZAJFWXA3DFNVSW45DTEBBW63LQNRSXIZJAKN2GC3TEMFZGI4Y=",
      .encoded_len   = 56,
      .decoded_est   = 35,
#elif (TEST_ENCODE == TICS_ENCODE_BASE32HEX)
      .encoded       = "AH4K6KP095MN0R35DLIMST3J411MURBGDHIN8P90ADQ62RJ4C5P68SO=",
      .encoded_len   = 56,
      .decoded_est   = 35,
#elif (TEST_ENCODE == TICS_ENCODE_BASE64)
      .encoded       = "VElDUyBJbXBsZW1lbnRzIENvbXBsZXRlIFN0YW5kYXJkcw==",
      .encoded_len   = 48,
      .decoded_est   = 36,
#endif
   },


{  .decoded       = "TICS Implements Complete Standards.",
      .decoded_len   = 35,
#if (TEST_ENCODE == TICS_ENCODE_BASE16)
      .encoded       = "5449435320496d706c656d656e747320436f6d706c657465205374616e64617264732e",
      .encoded_len   = 70,
      .decoded_est   = 35,
#elif (TEST_ENCODE == TICS_ENCODE_BASE32)
      .encoded       = "KREUGUZAJFWXA3DFNVSW45DTEBBW63LQNRSXIZJAKN2GC3TEMFZGI4ZO",
      .encoded_len   = 56,
      .decoded_est   = 35,
#elif (TEST_ENCODE == TICS_ENCODE_BASE32HEX)
      .encoded       = "AH4K6KP095MN0R35DLIMST3J411MURBGDHIN8P90ADQ62RJ4C5P68SPE",
      .encoded_len   = 56,
      .decoded_est   = 35,
#elif (TEST_ENCODE == TICS_ENCODE_BASE64)
      .encoded       = "VElDUyBJbXBsZW1lbnRzIENvbXBsZXRlIFN0YW5kYXJkcy4=",
      .encoded_len   = 48,
      .decoded_est   = 36,
#endif
   },


   {  .decoded       = "TICS Implements Complete Standards.a",
      .decoded_len   = 36,
#if (TEST_ENCODE == TICS_ENCODE_BASE32)
      .encoded       = "KREUGUZAJFWXA3DFNVSW45DTEBBW63LQNRSXIZJAKN2GC3TEMFZGI4ZOME======",
      .encoded_len   = 64,
      .decoded_est   = 40,
#elif (TEST_ENCODE == TICS_ENCODE_BASE32HEX)
      .encoded       = "AH4K6KP095MN0R35DLIMST3J411MURBGDHIN8P90ADQ62RJ4C5P68SPEC4======",
      .encoded_len   = 64,
      .decoded_est   = 40,
#elif (TEST_ENCODE == TICS_ENCODE_BASE64)
      .encoded       = "VElDUyBJbXBsZW1lbnRzIENvbXBsZXRlIFN0YW5kYXJkcy5h",
      .encoded_len   = 48,
      .decoded_est   = 36,
#endif
   },


   {  .decoded       = "TICS Implements Complete Standards.ab",
      .decoded_len   = 37,
#if (TEST_ENCODE == TICS_ENCODE_BASE32)
      .encoded       = "KREUGUZAJFWXA3DFNVSW45DTEBBW63LQNRSXIZJAKN2GC3TEMFZGI4ZOMFRA====",
      .encoded_len   = 64,
      .decoded_est   = 40,
#elif (TEST_ENCODE == TICS_ENCODE_BASE32HEX)
      .encoded       = "AH4K6KP095MN0R35DLIMST3J411MURBGDHIN8P90ADQ62RJ4C5P68SPEC5H0====",
      .encoded_len   = 64,
      .decoded_est   = 40,
#endif
   },


   {  .encoded       = NULL,
      .decoded       = NULL,
      .encoded_len   = 0,
      .decoded_est   = 0,
      .decoded_len   = 0,
   }
};

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
   const char *      encode_str;

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

#ifdef XTEST_ENCODING
   if ((encode_str = tics_encoding2str(-1)) == NULL)
#else
   if ((encode_str = tics_encoding2str(TEST_ENCODE)) == NULL)
#endif
   {  fprintf(stderr, "%s: tics_encoding2str(): unknown encoding\n", PROGRAM_NAME);
      return(1);
   };

   if ((test_convenience(encode_str)))
      return(1);

   return(0);
}


int
test_convenience(
         const char *                  encode_str )
{
   ssize_t           rc;
   int               count;
   int               pass;
   uint8_t           buff[TEST_BUFF_LEN];
   uint8_t           pad[TEST_BUFF_LEN];
   test_data_t *     rec;


   if (!(quiet))
      printf("testing %s encode functions ...\n", encode_str);

   for(count = 0; ((test_data[count].encoded)); count++)
   {  rec = &test_data[count];
      if ((verbose))
         printf("   testing set %i\n", count);
      if (verbose > 1)
      {  printf("      Test Data (decoded): \"%s\"\n", rec->decoded);
         printf("      Test Data (encoded): \"%s\"\n", rec->encoded);
      };

#if defined(XFAIL_ENCODED_SIZE)
      if ((rc = tics_encoded_size(-1, rec->decoded_len)) < TICS_SUCCESS)
#else
      if ((rc = tics_encoded_size(TEST_ENCODE, rec->decoded_len)) < TICS_SUCCESS)
#endif
      {  fprintf(stderr, "%s: pass %i: tics_encoded_size(): %s\n", PROGRAM_NAME, count, tics_strerror((int)rc));
         return(1);
      };
      if (rc != (ssize_t)rec->encoded_len)
      {  fprintf(stderr, "%s: pass %i: tics_encoded_size(): returned incorrect estimated encoded size\n", PROGRAM_NAME, count);
         return(1);
      };

      for(pass = 0; (pass < 2); pass++)
      {  if (pass == 0)
         {  memset(pad,  0x55, sizeof(pad));
            memset(buff, 0x55, sizeof(pad));
         } else
         {  memset(pad,  0xaa, sizeof(pad));
            memset(buff, 0xaa, sizeof(pad));
         };
         if (verbose > 2)
            printf("         testing results with 0x%02x pad ...\n", pad[0]);

         if ((rc = tics_encode(TEST_ENCODE, rec->decoded, rec->decoded_len, (char *)buff, sizeof(buff))) < TICS_SUCCESS)
         {  fprintf(stderr, "%s: pass %i: tics_encode(): %s\n", PROGRAM_NAME, count, tics_strerror((int)rc));
            return(1);
         };
         if (rc != (ssize_t)rec->encoded_len)
         {  fprintf(stderr, "%s: pass %i: tics_encode(): returned incorrect encoded size\n", PROGRAM_NAME, count);
            return(1);
         };

         if ((memcmp(buff, rec->encoded, rec->encoded_len)))
         {  fprintf(stderr, "%s: pass %i: padding 0x%02x: tics_encode() message does not match\n", PROGRAM_NAME, count, pad[0]);
            return(1);
         };
         if ((memcmp(&buff[rec->encoded_len], pad, rec->encoded_len)))
         {  fprintf(stderr, "%s: pass %i: padding 0x%02x: tics_encode() wrote data past buffer\n", PROGRAM_NAME, count, pad[0]);
            return(1);
         };
      };
   };

   if ((verbose))
      printf("\n");
   if (!(quiet))
      printf("testing %s decode functions ...\n", encode_str);

   for(count = 0; ((test_data[count].encoded)); count++)
   {  rec = &test_data[count];
      if ((verbose))
         printf("   testing set %i\n", count);
      if (verbose > 1)
      {  printf("      Test Data (decoded): \"%s\"\n", rec->decoded);
         printf("      Test Data (encoded): \"%s\"\n", rec->encoded);
      };

      if ((rc = tics_decoded_size(TEST_ENCODE, rec->encoded_len)) < TICS_SUCCESS)
      {  fprintf(stderr, "%s: pass %i: tics_decoded_size(): %s\n", PROGRAM_NAME, count, tics_strerror((int)rc));
         return(1);
      };
      if (rc != (ssize_t)rec->decoded_est)
      {  fprintf(stderr, "%s: pass %i: tics_decoded_size(): returned incorrect estimated decoded size\n", PROGRAM_NAME, count);
         return(1);
      };

      if ((rc = tics_encoding_verify(TEST_ENCODE, rec->encoded, rec->encoded_len)) < TICS_SUCCESS)
      {  fprintf(stderr, "%s: pass %i: tics_encoding_verify(): %s\n", PROGRAM_NAME, count, tics_strerror((int)rc));
         return(1);
      };
      if (rc != (ssize_t)rec->decoded_len)
      {  fprintf(stderr, "%s: pass %i: tics_encoding_verify(): returned incorrect decoded size\n", PROGRAM_NAME, count);
         return(1);
      };

      for(pass = 0; (pass < 2); pass++)
      {  if (pass == 0)
         {  memset(pad,  0x55, sizeof(pad));
            memset(buff, 0x55, sizeof(pad));
         } else
         {  memset(pad,  0xaa, sizeof(pad));
            memset(buff, 0xaa, sizeof(pad));
         };
         if (verbose > 2)
            printf("         testing results with 0x%02x pad ...\n", pad[0]);

         if ((rc = tics_decode(TEST_ENCODE, rec->encoded, rec->encoded_len, (char *)buff, sizeof(buff))) < TICS_SUCCESS)
         {  fprintf(stderr, "%s: pass %i: tics_decode(): %s\n", PROGRAM_NAME, count, tics_strerror((int)rc));
            return(1);
         };
         if (rc != (ssize_t)rec->decoded_len)
         {  fprintf(stderr, "%s: pass %i: tics_decode(): returned incorrect decoded size\n", PROGRAM_NAME, count);
            return(1);
         };

         if ((memcmp(buff, rec->decoded, rec->decoded_len)))
         {  fprintf(stderr, "%s: pass %i: padding 0x%02x: tics_decode() message does not match\n", PROGRAM_NAME, count, pad[0]);
            return(1);
         };
         if ((memcmp(&buff[rec->decoded_len], pad, rec->decoded_len)))
         {  fprintf(stderr, "%s: pass %i: padding 0x%02x: tics_decode() wrote data past buffer\n", PROGRAM_NAME, count, pad[0]);
            return(1);
         };
      };
   };

   return(0);
}

/* end of source */
