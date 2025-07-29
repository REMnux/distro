/* system_check_predefs.h -- check pre-defined macros

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2025 Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer
   <markus@oberhumer.com>
 */

// windows defines
#if defined(__CYGWIN32__) && !defined(__CYGWIN__)
#error "missing __CYGWIN__"
#endif
#if defined(__CYGWIN64__) && !defined(__CYGWIN__)
#error "missing __CYGWIN__"
#endif
#if defined(__CYGWIN__) && defined(_WIN32)
#error "unexpected _WIN32"
#endif
#if defined(__CYGWIN__) && defined(_WIN64)
#error "unexpected _WIN64"
#endif
#if defined(__MINGW64__) && !defined(__MINGW32__)
#error "missing __MINGW32__"
#endif
#if defined(__MINGW32__) && !defined(_WIN32)
#error "missing _WIN32"
#endif
#if defined(__MINGW64__) && !defined(_WIN64)
#error "missing _WIN64"
#endif
#if defined(_WIN64) && !defined(_WIN32)
#error "missing _WIN32"
#endif

// available since gcc-4.3 (2008), clang-2.7 (2010) and msvc-20XX
#if !defined(__COUNTER__)
#error "missing __COUNTER__"
#endif

// fundamental type sizes - these are pre-defined since gcc-4.3 (2008) and clang-2.8 (2010)
#if defined(__clang__) || defined(__GNUC__)
#if !defined(__SIZEOF_SHORT__)
#error "missing __SIZEOF_SHORT__"
#endif
#if !defined(__SIZEOF_INT__)
#error "missing __SIZEOF_INT__"
#endif
#if !defined(__SIZEOF_LONG__)
#error "missing __SIZEOF_LONG__"
#endif
#if !defined(__SIZEOF_LONG_LONG__)
#error "missing __SIZEOF_LONG_LONG__"
#endif
#if !defined(__SIZEOF_PTRDIFF_T__)
#error "missing __SIZEOF_PTRDIFF_T__"
#endif
#if !defined(__SIZEOF_SIZE_T__)
#error "missing __SIZEOF_SIZE_T__"
#endif
#if !defined(__SIZEOF_POINTER__)
#error "missing __SIZEOF_POINTER__"
#endif
#endif

// fundamental types - these are pre-defined since gcc-4.5 (2010) and clang-3.5 (2014)
#if defined(__clang__) || defined(__GNUC__)
#if !defined(__PTRDIFF_TYPE__)
#error "missing __PTRDIFF_TYPE__"
#endif
#if !defined(__SIZE_TYPE__)
#error "missing __SIZE_TYPE__"
#endif
#if !defined(__INTPTR_TYPE__)
#error "missing __INTPTR_TYPE__"
#endif
#if !defined(__UINTPTR_TYPE__)
#error "missing __UINTPTR_TYPE__"
#endif
#endif
#if defined(__PTRADDR_TYPE__) && !defined(__PTRADDR_WIDTH__)
#error "missing __PTRADDR_WIDTH__"
#elif defined(__PTRADDR_WIDTH__) && !defined(__PTRADDR_TYPE__)
#error "missing __PTRADDR_TYPE__"
#endif

// byte order - these are pre-defined since gcc-4.6 (2011) and clang-3.2 (2012)
#if defined(__clang__) || defined(__GNUC__)
#if !defined(__ORDER_BIG_ENDIAN__) || (__ORDER_BIG_ENDIAN__ + 0 == 0)
#error "missing __ORDER_BIG_ENDIAN__"
#endif
#if !defined(__ORDER_LITTLE_ENDIAN__) || (__ORDER_LITTLE_ENDIAN__ + 0 == 0)
#error "missing __ORDER_LITTLE_ENDIAN__"
#endif
#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ + 0 == 0)
#error "missing __BYTE_ORDER__"
#endif
#if !defined(__ORDER_BIG_ENDIAN__) || (__ORDER_BIG_ENDIAN__ + 0 != 4321)
#error "unexpected __ORDER_BIG_ENDIAN__"
#endif
#if !defined(__ORDER_LITTLE_ENDIAN__) || (__ORDER_LITTLE_ENDIAN__ + 0 != 1234)
#error "unexpected __ORDER_LITTLE_ENDIAN__"
#endif
#if (__BYTE_ORDER__ != __ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "unexpected __BYTE_ORDER__"
#endif
#endif

// pic and pie
#if defined(__PIC__) && defined(__pic__)
#if (__PIC__ + 0) != (__pic__ + 0)
#error "unexpected __PIC__ vs __pic__ mismatch"
#endif
#endif
#if defined(__PIC__)
#if (__PIC__ != 1) && (__PIC__ != 2)
#error "unexpected __PIC__ value"
#endif
#endif
#if defined(__pic__)
#if (__pic__ != 1) && (__pic__ != 2)
#error "unexpected __pic__ value"
#endif
#endif
#if defined(__PIE__) && defined(__pie__)
#if (__PIE__ + 0) != (__pie__ + 0)
#error "unexpected __PIE__ vs __pie__ mismatch"
#endif
#endif
#if defined(__PIE__)
#if (__PIE__ != 1) && (__PIE__ != 2)
#error "unexpected __PIE__ value"
#endif
#endif
#if defined(__pie__)
#if (__pie__ != 1) && (__pie__ != 2)
#error "unexpected __pie__ value"
#endif
#endif

/* vim:set ts=4 sw=4 et: */
