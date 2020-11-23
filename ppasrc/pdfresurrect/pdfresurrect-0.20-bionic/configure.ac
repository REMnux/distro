#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT


# Install prefix
AC_PREFIX_DEFAULT(/usr/local)


# Checks for programs, and clears CFLAGS during the check.
X="$CFLAGS"
CFLAGS=""
AC_PROG_CC
CFLAGS="$X"


# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T


# Check for functions
AC_CHECK_FUNCS([strdup strtol])


# Initialize CFLAGS.  If it is empty set optimization,
# otherwise the user has a CFLAGS set, so use that.
if test "xyz$CFLAGS" = "xyz"; then
  AM_CFLAGS="-O3 -Wall"
else
  AM_CFLAGS="$CFLAGS"
fi


# Macros
AC_ARG_ENABLE([debug],
              [AC_HELP_STRING([--enable-debug], [Enable debugging output])],
              [AM_CFLAGS=" -O0 -g3 -DDEBUG -Wall"],
              [AM_CFLAGS+=""])

AC_SUBST([AM_CFLAGS])


AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset mkdir strchr strrchr strstr])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
