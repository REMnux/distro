/* riscv64 nrv2b_d.S -- RISCV64 decompressor for NRV2B

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
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

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>

   John F. Reiser
   <jreiser@users.sourceforge.net>
*/

#ifndef NO_METHOD_CHECK
        addi pre8,meth,-M_NRV2B_LE32; bnez pre8,not_n2b
#endif
        lui bits,0x80000  // (1<<31): empty; force refill
        li disp,-1  // initial displacement

#undef  DEBUG_NRV
#define DEBUG_NRV 0
#if DEBUG_NRV  //{
#define LEN_ROV 0x100000
#define dst0  x31
#define src0  x30
#define hi_rov x29
#define prov  x28
        mv dst0,dst
        mv src0,src
        mov hi_rov,sp
        li prov,LEN_ROV
        sub prov,sp,prov
#endif  // DEBUG_NRV }

        j top_n2b

lit_n2b:
        addi src,src,1; sb pre8,(dst)
        addi dst,dst,1
top_n2b:
        lbu pre8,(src)  # prefetch: literal, or bottom 8 bits of offset
        jnextb1yp lit_n2b
#define off val
#if DEBUG_NRV  //{
    sub off,src,src0
    sw off,0(prov)
    sw bits,4(prov)
#endif  // DEBUG_NRV }
        li off,1  # the msb
offmore_n2b:
        getnextbp(off)
        jnextb0np offmore_n2b

        addiw off,off,-3; bltz off,len_n2b  # use previous offset
        slli  off,off,8; addi src,src,1  # account for previous fetch
// XXX 2GB; addw needs sign extend (32-->64) at EOF
        addw  off,off,pre8; lbu pre8,0(src)  # prefecth
        xori disp,off,~0  # no xoriw, so need previous addw
#undef off
        beqz disp,l_n2b_EOF
len_n2b:
#define off ta
        li off,1  # [add 1==off to len from ss11]
#define len val
        li len,0; getnextb(len); getnextb(len)  # two bits
        bnez len,gotlen_n2b  # raw 1,2,3 ==> 2,3,4 [add 1==off to len from 2 bits]
        li off,3  # raw 2.. ==> 5..  [add 3==off to len from ss11]

        li len,1  # the msb
lenmore_n2b:
        getnextb(len)
        jnextb0n lenmore_n2b
gotlen_n2b:
        add len,len,off
        li ta,-0xd00
        sltu ta,disp,ta
        add len,len,ta  # len += (disp < -0xd00)
#undef off

#if DEBUG_NRV  //{
    bgeu prov,hi_rov,0f
    sub ta,dst,dst0
    sw  ta,   2*4(prov)
    sb len,3+ 2*4(prov)
    sw disp,  3*4(prov)
    addi prov,prov,4*4
0:
#endif  // DEBUG_NRV }
#undef len

        jalr 0x32(x5)  # call copy
        j top_n2b

l_n2b_EOF:
#if DEBUG_NRV  //{
        li ta,LEN_ROV
        add sp,sp,ta
#endif  // DEBUG_NRV }
        j eof_n2b

not_n2b:
        # fall into daisy chain
/*
vi:ts=8:et:nowrap
*/

