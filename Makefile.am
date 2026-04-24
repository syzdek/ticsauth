#
#   TICS Authenticator
#   Copyright (C) 2026 David M. Syzdek <david@syzdek.net>.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of David M. Syzdek nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M SYZDEK BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   @configure_input@
#
#   Makefile.am - automate compiling on a unix platform
#

# Sub directories
SUBDIRS					=
DIST_SUBDIRS				=

# GNU make options
V					= 0

# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 \
					  -DHAVE_CONFIG_H=1 \
					  -I$(top_builddir)/include \
					  -I$(top_srcdir)/include \
					  -DLOCALSTATEDIR="\"$(localstatedir)\"" \
					  -DRUNSTATEDIR="\"$(runstatedir)\"" \
					  -DSYSCONFDIR="\"$(sysconfdir)\""
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
DEFS					=


# directory locations
moddir					= $(pkglibexecdir)/modules


# automake targets
check_PROGRAMS				=
doc_DATA				= AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  NEWS.md \
					  README.md \
					  TODO.md
html_DATA				=
include_HEADERS				= include/ticsauth.h
lib_LTLIBRARIES				= lib/libticsauth.la
lib_LIBRARIES				=
man_MANS				=
info_TEXINFOS				=
noinst_LTLIBRARIES			=
noinst_LIBRARIES			=
noinst_HEADERS				= include/ticsauth_noinst.h
noinst_PROGRAMS				=
bin_PROGRAMS				=
bin_SCRIPTS				=
pkgdata_DATA				=
sbin_SCRIPTS				=
sbin_PROGRAMS				=
mod_LTLIBRARIES				=
EXTRA_PROGRAMS				= $(TESTS)
EXTRA					=


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				=
TESTS					= tests/basexx-base16-dec \
					  tests/basexx-base16-enc \
					  tests/basexx-base16-ver \
					  tests/basexx-base32-dec \
					  tests/basexx-base32-enc \
					  tests/basexx-base32-ver \
					  tests/basexx-base32hex-dec \
					  tests/basexx-base32hex-enc \
					  tests/basexx-base32hex-ver \
					  tests/basexx-base64-dec \
					  tests/basexx-base64-enc \
					  tests/basexx-base64-ver \
					  tests/hash-md5 \
					  tests/hash-md5-ctx \
					  tests/hash-md5-seg \
					  tests/hash-md5-str \
					  tests/hash-sha1 \
					  tests/hash-sha1-ctx \
					  tests/hash-sha1-seg \
					  tests/hash-sha1-str \
					  tests/hash-sha224 \
					  tests/hash-sha224-ctx \
					  tests/hash-sha224-seg \
					  tests/hash-sha224-str \
					  tests/hash-sha256 \
					  tests/hash-sha256-ctx \
					  tests/hash-sha256-seg \
					  tests/hash-sha256-str \
					  tests/hash-sha384 \
					  tests/hash-sha384-ctx \
					  tests/hash-sha384-seg \
					  tests/hash-sha384-str \
					  tests/hash-sha512 \
					  tests/hash-sha512-ctx \
					  tests/hash-sha512-seg \
					  tests/hash-sha512-str \
					  tests/hmac-md5-ctx \
					  tests/hmac-md5-seg \
					  tests/hmac-md5-str \
					  tests/hmac-sha1-ctx \
					  tests/hmac-sha1-seg \
					  tests/hmac-sha1-str \
					  tests/hmac-sha224-ctx \
					  tests/hmac-sha224-seg \
					  tests/hmac-sha224-str \
					  tests/hmac-sha256-ctx \
					  tests/hmac-sha256-seg \
					  tests/hmac-sha256-str \
					  tests/hmac-sha384-ctx \
					  tests/hmac-sha384-seg \
					  tests/hmac-sha384-str \
					  tests/hmac-sha512-ctx \
					  tests/hmac-sha512-seg \
					  tests/hmac-sha512-str \
					  tests/proofofconcept \
					  $(XFAIL_TESTS)
XFAIL_TESTS				= tests/xhash-algo \
					  tests/xhash-result1 \
					  tests/xhash-result2 \
					  tests/xhash-result3
EXTRA_MANS				=
EXTRA_DIST				= AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  NEWS.md \
					  README.md \
					  TODO.md \
					  lib/libticsauth/libticsauth.sym \
					  doc/standards/rfc1321.txt \
					  doc/standards/rfc2104.txt \
					  doc/standards/rfc2202.txt \
					  doc/standards/rfc3174.txt \
					  doc/standards/rfc3874.txt \
					  doc/standards/rfc4226.txt \
					  doc/standards/rfc4231.txt \
					  doc/standards/rfc4634.txt \
					  doc/standards/rfc6151.txt \
					  doc/standards/rfc6234.txt \
					  doc/standards/rfc6238.txt \
					  doc/standards/rfc5741.txt \
					  doc/standards/standards.txt
CLEANFILES				= $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  $(EXTRA_PROGRAMS) \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.txz \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings \
					  CFLAGS="$(CFLAGS)" \
					  CPPFLAGS="$(CPPFLAGS)" \
					  LDFLAGS="$(LDFLAGS)"


# conditional build


# macros for lib/libticsauth.la
lib_libticsauth_la_DEPENDENCIES		= Makefile config.h lib/libticsauth/libticsauth.sym
lib_libticsauth_la_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libvicus
lib_libticsauth_la_LDFLAGS		= -rpath'$(libdir)' \
					  -version-info $(LIB_VERSION_INFO) \
					  $(AM_LDFLAGS) \
					  -export-symbols $(srcdir)/lib/libticsauth/libticsauth.sym
lib_libticsauth_la_SOURCES		= include/ticsauth.h \
					  include/ticsauth_noinst.h \
					  lib/libticsauth/libticsauth.h \
					  lib/libticsauth/lencoding.c \
					  lib/libticsauth/lhash.c \
					  lib/libticsauth/lhash.h \
					  lib/libticsauth/lhash-md5.c \
					  lib/libticsauth/lhash-md5.h \
					  lib/libticsauth/lhash-sha1.c \
					  lib/libticsauth/lhash-sha1.h \
					  lib/libticsauth/lhash-sha256.c \
					  lib/libticsauth/lhash-sha256.h \
					  lib/libticsauth/lhash-sha512.c \
					  lib/libticsauth/lhash-sha512.h \
					  lib/libticsauth/lhmac.c \
					  lib/libticsauth/lhmac.h \
					  lib/libticsauth/lmisc.c


# macros for tests/basexx-base16-dec
tests_basexx_base16_dec_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base16_dec_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base16_dec_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE16_DEC=1
tests_basexx_base16_dec_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base16.c


# macros for tests/basexx-base16-enc
tests_basexx_base16_enc_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base16_enc_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base16_enc_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE16_ENC=1
tests_basexx_base16_enc_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base16.c


# macros for tests/basexx-base16-ver
tests_basexx_base16_ver_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base16_ver_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base16_ver_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE16_VER=1
tests_basexx_base16_ver_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base16.c


# macros for tests/basexx-base32-dec
tests_basexx_base32_dec_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base32_dec_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base32_dec_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE32_DEC=1
tests_basexx_base32_dec_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base32.c


# macros for tests/basexx-base32-enc
tests_basexx_base32_enc_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base32_enc_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base32_enc_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE32_ENC=1
tests_basexx_base32_enc_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base32.c


# macros for tests/basexx-base32-ver
tests_basexx_base32_ver_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base32_ver_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base32_ver_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE32_VER=1
tests_basexx_base32_ver_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base32.c

# macros for tests/basexx-base32hex-dec
tests_basexx_base32hex_dec_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base32hex_dec_LDADD	= $(lib_LTLIBRARIES)
tests_basexx_base32hex_dec_CFLAGS	= $(AM_CFLAGS) -DTEST_BASE32HEX_DEC=1
tests_basexx_base32hex_dec_SOURCES	= tests/tests.h tests/test-basexx.c tests/data-base32hex.c


# macros for tests/basexx-base32hex-enc
tests_basexx_base32hex_enc_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base32hex_enc_LDADD	= $(lib_LTLIBRARIES)
tests_basexx_base32hex_enc_CFLAGS	= $(AM_CFLAGS) -DTEST_BASE32HEX_ENC=1
tests_basexx_base32hex_enc_SOURCES	= tests/tests.h tests/test-basexx.c tests/data-base32hex.c


# macros for tests/basexx-base32hex-ver
tests_basexx_base32hex_ver_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base32hex_ver_LDADD	= $(lib_LTLIBRARIES)
tests_basexx_base32hex_ver_CFLAGS	= $(AM_CFLAGS) -DTEST_BASE32HEX_VER=1
tests_basexx_base32hex_ver_SOURCES	= tests/tests.h tests/test-basexx.c tests/data-base32hex.c


# macros for tests/basexx-base64-dec
tests_basexx_base64_dec_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base64_dec_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base64_dec_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE64_DEC=1
tests_basexx_base64_dec_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base64.c


# macros for tests/basexx-base64-enc
tests_basexx_base64_enc_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base64_enc_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base64_enc_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE64_ENC=1
tests_basexx_base64_enc_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base64.c


# macros for tests/basexx-base64-ver
tests_basexx_base64_ver_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_basexx_base64_ver_LDADD		= $(lib_LTLIBRARIES)
tests_basexx_base64_ver_CFLAGS		= $(AM_CFLAGS) -DTEST_BASE64_VER=1
tests_basexx_base64_ver_SOURCES		= tests/tests.h tests/test-basexx.c tests/data-base64.c


# macros for tests/hash-md5
tests_hash_md5_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_md5_LDADD			= $(lib_LTLIBRARIES)
tests_hash_md5_CFLAGS			= $(AM_CFLAGS) -DTEST_HASH=TICS_HASH_MD5
tests_hash_md5_SOURCES			= tests/xtest-hash.c


# macros for tests/hash-md5-ctx
tests_hash_md5_ctx_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_md5_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hash_md5_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_MD5_CTX=1
tests_hash_md5_ctx_SOURCES		= tests/tests.h tests/test-hash.c tests/data-md5.c


# macros for tests/hash-md5-seg
tests_hash_md5_seg_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_md5_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hash_md5_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_MD5_SEG=1
tests_hash_md5_seg_SOURCES		= tests/tests.h tests/test-hash.c tests/data-md5.c


# macros for tests/hash-md5-str
tests_hash_md5_str_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_md5_str_LDADD		= $(lib_LTLIBRARIES)
tests_hash_md5_str_CFLAGS		= $(AM_CFLAGS) -DTEST_MD5_STR=1
tests_hash_md5_str_SOURCES		= tests/tests.h tests/test-hash.c tests/data-md5.c


# macros for tests/hash-sha1-ctx
tests_hash_sha1_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha1_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha1_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA1_CTX=1
tests_hash_sha1_ctx_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha1.c


# macros for tests/hash-sha1-seg
tests_hash_sha1_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha1_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha1_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA1_SEG=1
tests_hash_sha1_seg_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha1.c


# macros for tests/hash-sha1-str
tests_hash_sha1_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha1_str_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha1_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA1_STR=1
tests_hash_sha1_str_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha1.c


# macros for tests/hash-sha224-ctx
tests_hash_sha224_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha224_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha224_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA224_CTX=1
tests_hash_sha224_ctx_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha224.c


# macros for tests/hash-sha224-seg
tests_hash_sha224_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha224_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha224_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA224_SEG=1
tests_hash_sha224_seg_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha224.c


# macros for tests/hash-sha224-str
tests_hash_sha224_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha224_str_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha224_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA224_STR=1
tests_hash_sha224_str_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha224.c


# macros for tests/hash-sha256-ctx
tests_hash_sha256_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha256_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha256_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA256_CTX=1
tests_hash_sha256_ctx_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha256.c


# macros for tests/hash-sha256-seg
tests_hash_sha256_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha256_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha256_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA256_SEG=1
tests_hash_sha256_seg_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha256.c


# macros for tests/hash-sha256-str
tests_hash_sha256_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha256_str_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha256_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA256_STR=1
tests_hash_sha256_str_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha256.c


# macros for tests/hash-sha384-ctx
tests_hash_sha384_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha384_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha384_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA384_CTX=1
tests_hash_sha384_ctx_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha384.c


# macros for tests/hash-sha384-seg
tests_hash_sha384_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha384_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha384_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA384_SEG=1
tests_hash_sha384_seg_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha384.c


# macros for tests/hash-sha384-str
tests_hash_sha384_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha384_str_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha384_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA384_STR=1
tests_hash_sha384_str_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha384.c


# macros for tests/hash-sha512-ctx
tests_hash_sha512_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha512_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha512_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA512_CTX=1
tests_hash_sha512_ctx_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha512.c


# macros for tests/hash-sha512-seg
tests_hash_sha512_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha512_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha512_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA512_SEG=1
tests_hash_sha512_seg_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha512.c


# macros for tests/hash-sha512-str
tests_hash_sha512_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha512_str_LDADD		= $(lib_LTLIBRARIES)
tests_hash_sha512_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA512_STR=1
tests_hash_sha512_str_SOURCES		= tests/tests.h tests/test-hash.c tests/data-sha512.c


# macros for tests/hmac-md5-ctx
tests_hmac_md5_ctx_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_md5_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_md5_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_MD5_CTX=1
tests_hmac_md5_ctx_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-md5.c


# macros for tests/hmac-md5-seg
tests_hmac_md5_seg_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_md5_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_md5_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_MD5_SEG=1
tests_hmac_md5_seg_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-md5.c


# macros for tests/hmac-md5-str
tests_hmac_md5_str_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_md5_str_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_md5_str_CFLAGS		= $(AM_CFLAGS) -DTEST_MD5_STR=1
tests_hmac_md5_str_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-md5.c


# macros for tests/hash-sha1
tests_hash_sha1_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha1_LDADD			= $(lib_LTLIBRARIES)
tests_hash_sha1_CFLAGS			= $(AM_CFLAGS) -DTEST_HASH=TICS_HASH_SHA1
tests_hash_sha1_SOURCES			= tests/xtest-hash.c


# macros for tests/hmac-sha1-ctx
tests_hmac_sha1_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha1_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha1_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA1_CTX=1
tests_hmac_sha1_ctx_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha1.c


# macros for tests/hmac-sha1-seg
tests_hmac_sha1_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha1_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha1_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA1_SEG=1
tests_hmac_sha1_seg_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha1.c


# macros for tests/hmac-sha1-str
tests_hmac_sha1_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha1_str_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha1_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA1_STR=1
tests_hmac_sha1_str_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha1.c


# macros for tests/hash-sha224
tests_hash_sha224_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha224_LDADD			= $(lib_LTLIBRARIES)
tests_hash_sha224_CFLAGS		= $(AM_CFLAGS) -DTEST_HASH=TICS_HASH_SHA224
tests_hash_sha224_SOURCES		= tests/xtest-hash.c


# macros for tests/hmac-sha224-ctx
tests_hmac_sha224_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha224_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha224_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA224_CTX=1
tests_hmac_sha224_ctx_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha224.c


# macros for tests/hmac-sha224-seg
tests_hmac_sha224_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha224_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha224_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA224_SEG=1
tests_hmac_sha224_seg_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha224.c


# macros for tests/hmac-sha224-str
tests_hmac_sha224_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha224_str_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha224_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA224_STR=1
tests_hmac_sha224_str_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha224.c


# macros for tests/hash-sha256
tests_hash_sha256_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha256_LDADD			= $(lib_LTLIBRARIES)
tests_hash_sha256_CFLAGS		= $(AM_CFLAGS) -DTEST_HASH=TICS_HASH_SHA256
tests_hash_sha256_SOURCES		= tests/xtest-hash.c


# macros for tests/hmac-sha256-ctx
tests_hmac_sha256_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha256_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha256_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA256_CTX=1
tests_hmac_sha256_ctx_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha256.c


# macros for tests/hmac-sha256-seg
tests_hmac_sha256_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha256_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha256_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA256_SEG=1
tests_hmac_sha256_seg_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha256.c


# macros for tests/hmac-sha256-str
tests_hmac_sha256_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha256_str_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha256_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA256_STR=1
tests_hmac_sha256_str_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha256.c


# macros for tests/hash-sha384
tests_hash_sha384_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha384_LDADD			= $(lib_LTLIBRARIES)
tests_hash_sha384_CFLAGS		= $(AM_CFLAGS) -DTEST_HASH=TICS_HASH_SHA384
tests_hash_sha384_SOURCES		= tests/xtest-hash.c


# macros for tests/hmac-sha384-ctx
tests_hmac_sha384_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha384_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha384_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA384_CTX=1
tests_hmac_sha384_ctx_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha384.c


# macros for tests/hmac-sha384-seg
tests_hmac_sha384_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha384_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha384_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA384_SEG=1
tests_hmac_sha384_seg_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha384.c


# macros for tests/hmac-sha384-str
tests_hmac_sha384_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha384_str_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha384_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA384_STR=1
tests_hmac_sha384_str_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha384.c


# macros for tests/hash-sha512
tests_hash_sha512_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_hash_sha512_LDADD			= $(lib_LTLIBRARIES)
tests_hash_sha512_CFLAGS		= $(AM_CFLAGS) -DTEST_HASH=TICS_HASH_SHA512
tests_hash_sha512_SOURCES		= tests/xtest-hash.c


# macros for tests/hmac-sha512-ctx
tests_hmac_sha512_ctx_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha512_ctx_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha512_ctx_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA512_CTX=1
tests_hmac_sha512_ctx_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha512.c


# macros for tests/hmac-sha512-seg
tests_hmac_sha512_seg_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha512_seg_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha512_seg_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA512_SEG=1
tests_hmac_sha512_seg_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha512.c


# macros for tests/hmac-sha512-str
tests_hmac_sha512_str_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_hmac_sha512_str_LDADD		= $(lib_LTLIBRARIES)
tests_hmac_sha512_str_CFLAGS		= $(AM_CFLAGS) -DTEST_SHA512_STR=1
tests_hmac_sha512_str_SOURCES		= tests/tests.h tests/test-hmac.c tests/data-sha512.c


# macros for tests/proofofconcept
tests_proofofconcept_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_proofofconcept_LDADD		= $(lib_LTLIBRARIES)
tests_proofofconcept_SOURCES		= tests/tests.h \
					  tests/proofofconcept.c


# macros for tests/xhash-algo
tests_xhash_algo_DEPENDENCIES		= Makefile config.h $(lib_LTLIBRARIES)
tests_xhash_algo_LDADD			= $(lib_LTLIBRARIES)
tests_xhash_algo_CFLAGS			= $(AM_CFLAGS) -DXTEST_ALGORITHM=1
tests_xhash_algo_SOURCES		= tests/xtest-hash.c


# macros for tests/xhash-result1
tests_xhash_result1_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_xhash_result1_LDADD		= $(lib_LTLIBRARIES)
tests_xhash_result1_CFLAGS		= $(AM_CFLAGS) -DXFAIL_MD_RESULT1=1
tests_xhash_result1_SOURCES		= tests/xtest-hash.c


# macros for tests/xhash-result2
tests_xhash_result2_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_xhash_result2_LDADD		= $(lib_LTLIBRARIES)
tests_xhash_result2_CFLAGS		= $(AM_CFLAGS) -DXFAIL_MD_RESULT1=2
tests_xhash_result2_SOURCES		= tests/xtest-hash.c


# macros for tests/xhash-result3
tests_xhash_result3_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_xhash_result3_LDADD		= $(lib_LTLIBRARIES)
tests_xhash_result3_CFLAGS		= $(AM_CFLAGS) -DXFAIL_MD_RESULT1=3
tests_xhash_result3_SOURCES		= tests/xtest-hash.c


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include contrib/bindletools/build-aux/makefile-subst.am
include contrib/bindletools/build-aux/makefile-version.am


# custom targets
.PHONY: git-clean

git-clean:
	git fsck --full --unreachable
	git gc --auto --aggressive


# local targets
install-exec-local:

install-data-local:

install-data-hook:

uninstall-local:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
