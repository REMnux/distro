/* nrv2d_d.S -- RiscV64 decompressor for NRV2D

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
        addi pre8,meth,-M_NRV2D_LE32; bnez pre8,not_n2d
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

        j top_n2d
lit_n2d:
        addi src,src,1; sb pre8,(dst)
        addi dst,dst,1
top_n2d:
        lbu pre8,(src)  # prefetch: literal, or bottom 8 bits of offset
        jnextb1yp lit_n2d
#define off val
#if DEBUG_NRV  //{
    sub off,src,src0
    sw off,0(prov)
    sw bits,4(prov)
#endif  // DEBUG_NRV }
        li off,1; j getoff_n2d  # the msb

off_n2d:
        addi off,off,-1
        getnextbp(off)
getoff_n2d:
        getnextbp(off)
        jnextb0np off_n2d

        addiw off,off,-3; bltz off,offprev_n2d  # use previous offset
        slli  off,off,8; addi src,src,1  # account for previous fetch
// XXX 2GB; addw needs sign extend (32-->64) at EOF
        addw  off,off,pre8; lbu pre8,0(src)  # prefecth
        xori disp,off,~0  # no xoriw, so need previous addw
#undef off
#define len val
        beqz disp,l_n2d_EOF
        andi len,disp,1; srai disp,disp,1  # len= 0 or 1
        j getlen_n2d

offprev_n2d:
        GETBIT; mv len,rbit  // m_len= 0,1
getlen_n2d:
        getnextb(len); bnez len,gotlen_n2d  // m_len= 0,1,2,3

        li len,1  # the msb
lenmore_n2d:
        getnextb(len)
        jnextb0n lenmore_n2d
        addi len,len,2  // m_len= 4..
gotlen_n2d:
        addi len,len,1  // len= (1,2,3,4) or 5..
off_check_n2d:
        li ta,-0x500
        sltu ta,disp,ta
        add len,len,ta  // len += (disp < -0x500);

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

        call copy
bot_n2d:  // In: 0==len
        j top_n2d

l_n2d_EOF:
#if DEBUG_NRV  //{
        li ta,LEN_ROV
        add sp,sp,ta
#endif  // DEBUG_NRV }
        j eof_n2d


#ifndef NO_METHOD_CHECK
not_n2d:
        push %rdi; pop %rsi  # src = arg1
#endif
        // fall into daisy chain
/*
vi:ts=8:et:nowrap
*/

