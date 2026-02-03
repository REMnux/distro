/* system_undefs.h -- undef system pre-defines

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

// some platform system headers may pre-define these, so undef to avoid conflicts
#undef _
#undef __
#undef ___
#undef ____
#undef _____
#undef MIPSEB
#undef MIPSEL
#undef PAGE_MASK
#undef PAGE_SIZE
#undef PPC
#undef R3000
#undef R4000
#undef SP
#undef SS
#undef WIN32
#undef WIN64
#undef WINNT
#undef dos
#undef far
#undef huge
#undef i386
#undef large
#undef linux
#undef mc68000
#undef mips
#undef near
#undef powerpc
#undef small
#undef tos
#undef unix

/* vim:set ts=4 sw=4 et: */
