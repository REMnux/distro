/* riscv64-getbit.h -- register definitions for de-compressor

   This file is part of the UPX executable compressor.

   Copyright (C) John F. Reiser
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

   John F. Reiser
   <jreiser@users.sourceforge.net>
*/
// Registers during NRV/UCL de-compress code.
// Chosen to fit in Risc-V Compact register subset
#define dst  x15  /* a5  rdi */
#define src  x14  /* a4  rsi */
#define disp x13  /* a3  rbp */
#define ta   x12  /* a2  rsp */
#define bits x11  /* a1  rbx */
#define rbit x10  /* a0  rax   rv */
#define pre8 x9   /* s1  rdx */
#define val  x8   /* s0  rcx   fp */

/* jump on next bit {0,1} with prediction {y==>likely, n==>unlikely} */
/* Prediction omitted for now. */

#define jnextb0np jnextb0yp
#define jnextb0yp GETBITp; beqz rbit,
#define jnextb1np jnextb1yp
#define jnextb1yp GETBITp; bnez rbit,
#define GETBITp \
        jalr x5

/* Same, but without prefetch (not useful for length of match.) */
#define jnextb0n jnextb0y
#define jnextb0y GETBIT; beqz rbit,
#define jnextb1n jnextb1y
#define jnextb1y GETBIT; bnez rbit,
#define GETBIT \
        jalr x5

/* rotate next bit into bottom bit of reg */
#define getnextbp(reg) GETBITp; slli reg,reg,1;  or reg,reg,rbit
#define getnextb(reg)  getnextbp(reg)

