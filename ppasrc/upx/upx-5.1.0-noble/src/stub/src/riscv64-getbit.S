/* riscv64-getbit.S -- low-level subroutines for de-compression

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

// Must be first in this file to make "jal x5,xin_..." work.
getbit:
        srliw rbit,bits,31  # hi bit of 32
        addw bits,bits,bits; beqz bits,refill
        ret
/* On refill: prefetch next byte, for latency reduction on literals and offsets. */
refill:
// Unaligned: profile RVA22U64 with required extension Ziccism allows trap (slow)
#if 0  //{
        lw bits,(src)
#else  //}{
     // lbu pre8,0(src)  # already done
        lbu bits,1(src);    slli bits,bits,1*8
        lbu rbit,2(src);    or   bits,bits,pre8
        lbu pre8,3(src);    slli rbit,rbit,2*8
                            or   bits,bits,rbit
                            slli pre8,pre8,3*8
                            or   bits,bits,pre8
#endif  //}
        addi src,src,4

        srliw rbit,bits,31  # hi bit of 4 bytes fetched
        slli bits,bits,1; lbu pre8,(src)  # prefetch
        addiw bits,bits,1  # the flag bit
        ret

copy:  // In: len, dst, disp; typically short: len <= 6
#define tmp ta
#define len val
        add tmp,dst,disp  # src
        add len,dst,len  # limit
        lbu pre8,0(tmp)  # prime the pump
0:
        sb  pre8,0(dst); addi dst,dst,1
        lbu pre8,1(tmp); addi tmp,tmp,1; bne dst,len,0b
        ret
#undef len
#undef tmp

