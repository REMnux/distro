/* system_features.h -- libc and libc++ features

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
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

#pragma once

#include "system_defs.h"

#if defined(__has_include)
#if __has_include(<features.h>)
#include <features.h> // for __GLIBC__ and __GLIBC_MINOR__
#endif
#endif

// libc++ hardenining
#if defined(__cplusplus) && 0 // TODO later

#if !defined(_LIBCPP_HARDENING_MODE)
#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ + 0 >= 18)
#if DEBUG
#define _LIBCPP_HARDENING_MODE _LIBCPP_HARDENING_MODE_DEBUG
#else
#define _LIBCPP_HARDENING_MODE _LIBCPP_HARDENING_MODE_EXTENSIVE
#endif
#endif // clang >= 18
#endif // _LIBCPP_HARDENING_MODE

#if !defined(_LIBCPP_ENABLE_ASSERTIONS)
#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ + 0 < 18)
#if DEBUG
#define _LIBCPP_ENABLE_ASSERTIONS 1
#endif
#endif // clang < 18
#endif // _LIBCPP_ENABLE_ASSERTIONS

#endif // TODO later

// aligned_alloc() was added in glibc-2.16
#if !defined(_LIBCPP_HAS_NO_LIBRARY_ALIGNED_ALLOCATION) && defined(__cplusplus)
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ + 0 == 2) &&                      \
    (__GLIBC_MINOR__ + 0 > 0) && (__GLIBC_MINOR__ + 0 < 16)
#define _LIBCPP_HAS_NO_LIBRARY_ALIGNED_ALLOCATION
#endif
#endif // _LIBCPP_HAS_NO_LIBRARY_ALIGNED_ALLOCATION

#if defined(_LIBCPP_HAS_NO_LIBRARY_ALIGNED_ALLOCATION) && defined(__cplusplus)
#if defined(__has_include)
#if __has_include(<__config>)
#include <__config>
#undef _LIBCPP_HAS_LIBRARY_ALIGNED_ALLOCATION
#undef _LIBCPP_HAS_ALIGNED_ALLOCATION
#define _LIBCPP_HAS_LIBRARY_ALIGNED_ALLOCATION 0
#define _LIBCPP_HAS_ALIGNED_ALLOCATION         0
#endif
#endif
#endif // _LIBCPP_HAS_NO_LIBRARY_ALIGNED_ALLOCATION

/* vim:set ts=4 sw=4 et: */
