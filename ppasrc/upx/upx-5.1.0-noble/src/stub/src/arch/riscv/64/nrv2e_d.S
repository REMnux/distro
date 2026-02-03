/* nrv2e_d.S -- RiscV64 decompressor for NRV2E

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
        addi pre8,meth,-M_NRV2E_LE32; bnez pre8,not_n2e
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

                        sw zero,0(prov)
        lw pre8,0(src); sw pre8,4(prov)
        lw pre8,4(src); sw pre8,8(prov)
        lw pre8,8(src); sw pre8,12(prov)
                              addi prov,prov,4*4
#endif  // DEBUG_NRV }

        j top_n2e

lit_n2e:
        addi src,src,1; sb pre8,(dst)
        addi dst,dst,1
top_n2e:
        lbu pre8,(src)  # prefetch: literal, or bottom 8 bits of offset
        jnextb1yp lit_n2e

#define off val
#if DEBUG_NRV  //{
    sub off,src,src0
    sw off, 0(prov)
    sw bits,4(prov)
#endif  // DEBUG_NRV }

        li off,1; j getoff_n2e  # the msb

off_n2e:
        addi off,off,-1
        getnextb(off)
getoff_n2e:
        getnextb(off)
        jnextb0np off_n2e

        addiw off,off,-3; bltz off,offprev_n2e
        slli off,off,8; addi src,src,1  # account for previous prefetch
        addw off,off,pre8; lbu pre8,0(src)  # prefetch
        xori disp,off,~0; beqz disp,l_n2e_EOF
#undef  off
#define len val
        andi len,disp,1; srai disp,disp,1
// point A: if (m_len)  # after the 'for (;;)' loop and the prev-vs-EOF test
len2or3:
        beqz len,len4or5
        GETBIT; addi len,rbit,2; j off_check_n2e
// point B: else if (getbit(bb))
len4or5:
        jnextb0np lenmore_n2e
        GETBIT; addi len,rbit,4; j off_check_n2e
// point C: else
lenmore_n2e:
        li len,1  # ss11 the msb
len_n2e:
        getnextb(len)
        jnextb0yp len_n2e
        addi len,len,6 - 2  # 6... but ss11 retval is 2 minimum
        j off_check_n2e

offprev_n2e:
        GETBIT; mv len,rbit; j len2or3

off_check_n2e:
        li ta,-0x500
        sltu ta,disp,ta
        add len,len,ta

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

copy_n2e:
        jalr 0x32(x5)  # call copy
        j top_n2e

l_n2e_EOF:
#if DEBUG_NRV  //{
        li ta,LEN_ROV
        add sp,sp,ta
#endif  // DEBUG_NRV }
        j eof_n2e

not_n2e:
        // fall into daisy chain

/*
vi:ts=8:et:nowrap
*/
