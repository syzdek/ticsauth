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
#   acinclude.m4 - custom m4 macros used by configure.ac
#


# AC_TICSAUTH_EXAMPLES()
# ______________________________________________________________________________
AC_DEFUN([AC_TICSAUTH_EXAMPLES],[dnl

   enableval=""
   AC_ARG_ENABLE(
      examples,
      [AS_HELP_STRING([--enable-examples], [build example programs])],
      [ EEXAMPLES=$enableval ],
      [ EEXAMPLES=$enableval ]
   )

   if test "x${EEXAMPLES}" == "xyes";then
      ENABLE_EXAMPLES=build
   else
      ENABLE_EXAMPLES=skip
   fi

   AM_CONDITIONAL([ENABLE_EXAMPLES],  [test "$ENABLE_EXAMPLES"  = "build"])
   AM_CONDITIONAL([DISABLE_EXAMPLES], [test "$ENABLE_EXAMPLES" != "build"])
])dnl


# AC_TICSAUTH_EXTRA_DOCS()
# ______________________________________________________________________________
AC_DEFUN([AC_TICSAUTH_EXTRA_DOCS],[dnl

   enableval=""
   AC_ARG_ENABLE(
      extra-docs,
      [AS_HELP_STRING([--enable-extra-docs], [install extra documentation])],
      [ EEXTRA_DOCS=$enableval ],
      [ EEXTRA_DOCS=$enableval ]
   )

   if test "x${EEXTRA_DOCS}" == "xyes";then
      ENABLE_EXTRA_DOCS=install
   else
      ENABLE_EXTRA_DOCS=skip
   fi

   AM_CONDITIONAL([ENABLE_EXTRA_DOCS],  [test "$ENABLE_EXTRA_DOCS"  = "install"])
   AM_CONDITIONAL([DISABLE_EXTRA_DOCS], [test "$ENABLE_EXTRA_DOCS" != "install"])
])dnl


# AC_TICSAUTH_EXTRA_TESTS()
# ______________________________________________________________________________
AC_DEFUN([AC_TICSAUTH_EXTRA_TESTS],[dnl

   enableval=""
   AC_ARG_ENABLE(
      extra-tests,
      [AS_HELP_STRING([--enable-extra-tests], [build extra checks programs])],
      [ EEXTRA_TESTS=$enableval ],
      [ EEXTRA_TESTS=$enableval ]
   )

   if test "x${EEXTRA_TESTS}" == "xyes";then
      ENABLE_ADDITIONAL_TESTS=build
   else
      ENABLE_ADDITIONAL_TESTS=skip
   fi

   AM_CONDITIONAL([ENABLE_ADDITIONAL_TESTS],  [test "$ENABLE_ADDITIONAL_TESTS"  = "build"])
   AM_CONDITIONAL([DISABLE_ADDITIONAL_TESTS], [test "$ENABLE_ADDITIONAL_TESTS" != "build"])
])dnl


# end of m4 file

