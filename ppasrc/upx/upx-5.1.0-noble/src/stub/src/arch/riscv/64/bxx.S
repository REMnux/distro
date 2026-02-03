/* riscv/64/bxx.S -- Riscv64 AUIPC Trick unfilter

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

#include "regs.h"

riscvbxx:  # (*f_unf)(xo->buf, out_len, h.b_cto8, h.b_ftid);

#define limit t0
#define ptr0  t1
#define r_aui t2

#define ptr  arg1
#define len  arg2
#define word1  arg2
#define ta   /*arg3*/ x12
#define   addr arg3
#define ftid arg4
#define   ilen  arg4
#define tb   arg5
#define word2 arg6

AUIPC= 0x17
#ifndef NO_METHOD_CHECK
        li ta,0x55; bne ta,ftid,rvf_end
#endif
        add limit,len,ptr  # fence post
        addi limit,limit,-8
        mv ptr0,ptr
rvf_top:
        lbu word1,0(ptr)  # lwu word1,0(ptr) unaligned little-endian
        li ilen,2
                      andi ta,word1,3; xori ta,ta,3; bnez ta,ilen2
        srli ta,word1,2; andi ta,ta,3; xori ta,ta,3; bnez ta,ilen4
        srli ta,word1,4; andi ta,ta,3; xori ta,ta,3; bnez ta,ilen6
        addi ilen,ilen,2  # 8 or more
ilen6:  addi ilen,ilen,2
ilen4:  addi ilen,ilen,2
ilen2:
        andi ta,word1,0x7f
        addi ta,ta,-AUIPC; bnez ta,rvf_bot

        lbu ta,   1(ptr); slli ta,ta,1*8; or word1,word1,ta  # rest of word1
        lbu ta,   2(ptr); slli ta,ta,2*8; or word1,word1,ta
        lbu ta,   3(ptr); slli ta,ta,3*8; or word1,word1,ta
        li ilen,8  # next is after word2

        lbu word2,4(ptr)  # lwu word2,4(ptr) unaligned little-endian
        lbu ta,   5(ptr); slli ta,ta,1*8; or word2,word2,ta
        lbu ta,   6(ptr); slli ta,ta,2*8; or word2,word2,ta
        lbu ta,   7(ptr); slli ta,ta,3*8; or word2,word2,ta
        srli ta,word2,7
        andi r_aui,ta,037

        lbu tb,1(ptr); slli addr,tb,3*8  # lwu addr,1(ptr) BIG_ENDIAN unaligned
        lbu tb,2(ptr); slli   tb,tb,2*8; or addr,addr,tb
        lbu tb,3(ptr); slli   tb,tb,1*8; or addr,addr,tb
        lbu tb,4(ptr);   andi tb,tb,0x7f   # lo byte is special
                         slli tb,tb,1;   or addr,addr,tb  # bits 7:1
        srli tb,word1,7; andi tb,tb,1;   or addr,addr,tb  # bit 0

        sub tb,ptr,ptr0  # hoisted amount
        sub addr,addr,tb # un-hoist

        srli tb,addr,11
        andi tb,tb,1
        slli tb,tb,12
        add addr,addr,tb  # sign-extension of 12-bit imm
        srli tb,addr,12
        slli tb,tb,12  # ~0xfff & addr
        slli r_aui,r_aui,7; or tb,tb,r_aui
        ori tb,tb,AUIPC
        sb tb,0(ptr); srli tb,tb,8  # sw tb,0(ptr) unaligned little-endian
        sb tb,1(ptr); srli tb,tb,8
        sb tb,2(ptr); srli tb,tb,8
        sb tb,3(ptr)

        slli addr,addr,20
        srli word2,word2,12
        or tb,addr,word2
        sb tb,4(ptr); srli tb,tb,8  # sw tb,4(ptr) unaligned little-endian
        sb tb,5(ptr); srli tb,tb,8
        sb tb,6(ptr); srli tb,tb,8
        sb tb,7(ptr)
rvf_bot:
        add ptr,ptr,ilen
        blt ptr,limit,rvf_top
rvf_end:
#ifndef NO_METHOD_CHECK
        ret
#endif

#undef limit
#undef ptr0
#undef r_aui

#undef ptr
#undef len
#undef word1
#undef ta
#undef   addr
#undef ftid
#undef   ilen
#undef tb
#undef word2
