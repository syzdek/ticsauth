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
examplesdir				= $(docdir)/examples


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
examples_DATA				=
EXTRA_PROGRAMS				= tests/proofofconcept
EXTRA					=


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				=
TESTS					= tests/proofofconcept
XFAIL_TESTS				=
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
					  lib/libticsauth/lhash-crc32.c \
					  lib/libticsauth/lhash-crc32.h \
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


# macros for tests/proofofconcept
tests_proofofconcept_DEPENDENCIES	= Makefile config.h $(lib_LTLIBRARIES)
tests_proofofconcept_LDADD		= $(lib_LTLIBRARIES)
tests_proofofconcept_SOURCES		= tests/tests.h \
					  tests/proofofconcept.c


# makefile includes
include examples/makefile-examples.am
include tests/makefile-basexx.am
include tests/makefile-hash.am
include tests/makefile-hmac.am
include tests/makefile-xbasexx.am
include tests/makefile-xhash.am
include tests/makefile-xhmac.am


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
