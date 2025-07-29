/* lzma_d.S -- MIPS R3000 decompressor for LZMA

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2025 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2025 Laszlo Molnar
   Copyright (C) 2000-2025 John F. Reiser
   Copyright (C) 2002-2025 Jens Medoch
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

   John F. Reiser                       Jens Medoch
   <jreiser@users.sourceforge.net>      <jssg@users.sourceforge.net>
 */

#include "macros.ash"
#include "bits.ash"

#define lxsrc    a0
#define lxsrclen a1
#define lxdst    a2
#define lxdstlen a3

#undef src  /* bits.ash */
#define src     lxsrc
#define lsrc    lxsrclen
#undef dst  /* bits.ash */
#define dst     lxdst
#define ldst    lxdstlen
#define meth     a4

/* asm/cachectl.h */
ICACHE= 1<<0
DCACHE= 1<<1

section     LZMA_ELF00 # (a0=lxsrc, a1=lxsrclen, a2=lxdst, a3= &lxdstlen)

/* LzmaDecode(a0=CLzmaDecoderState *,
        a1=src, a2=srclen, a3=*psrcdone,
        dst, dstlen, *pdstdone);
struct CLzmaDecoderState {
        uchar lit_context_bits;
        uchar lit_pos_bits;
        uchar pos_bits;
        uchar unused;
        struct CProb[LZMA_BASE_SIZE + (LZMA_LIT_SIZE<<n)];
};
*/

LZMA_BASE_NUM = 1846
LZMA_LIT_NUM  =  768

lxlzma_szframe  = 12*4
lxlzma_sv_pc    = 11*4
lxlzma_sv_sp    = 10*4
lxlzma_dst      =  9*4
lxlzma_dstdone  =  8*4
lxlzma_srcdone  =  7*4
lxlzma_retval   = lxlzma_srcdone

#define a4 t0
#define a5 t1
#define a6 t2
#define tmp at
  .set noat

#define M_LZMA 14
        lbu v0,-4(lxsrc)  # b_method
        li at,M_LZMA
        bne at,v0,not_lzma
          lbu t9,0(lxsrc)  # ((lit_context_bits + lit_pos_bits)<<3) | pos_bits
        li tmp,-2*LZMA_LIT_NUM
        lbu t8,1(lxsrc)  # (lit_pos_bits<<4) | lit_context_bits
        andi v0,t9,7  # pos_bits
        srl t9,t9,3  # (lit_context_bits + lit_pos_bits)
        sllv tmp,tmp,t9
        addiu tmp,tmp,-4 - 2*LZMA_BASE_NUM - lxlzma_szframe
        addu sp,sp,tmp  # alloca
                sw tmp,lxlzma_sv_sp(sp)  # dynamic frame size
        addiu a6,sp,lxlzma_dstdone
                sw ra, lxlzma_sv_pc(sp)
        lw    a5,0(lxdstlen)
                sw lxdst,lxlzma_dst(sp)
        move  a4,lxdst
        addiu a3,sp,lxlzma_srcdone
        addiu a2,lxsrclen,-2  # 2 header bytes
        addiu a1,lxsrc,2  # 2 header bytes
        addiu a0,sp,lxlzma_szframe  # &CLzamDecoderState
        sb     v0,2(a0)   # pos_bits
        andi tmp,t8,0xf
        sb   tmp, 0(a0)  # lit_context_bits
        srl  t8,t8,4
        bal lzma_decode
          sb   t8,1(a0)   # lit_pos_bits

/* It seems that for our uses the icache does not need to be invalidated,
   because no lines from the destination have ever been fetched.  However,
   if the dcache is write-back, then some of the results might not be in
   memory yet, and the icache could fetch stale data; so memory must be
   updated from dcache.
   The *next* call of the decompressor will tend to sweep much of the dcache
   anyway, because the probability history array (typically ushort[7990] or
   ushort[14134]) gets initialized.
*/
        sw v0,lxlzma_retval(sp)  # return value from decompression

        lw a0,lxlzma_dst(sp)
        lw a1,lxlzma_dstdone(sp)
        li a2,ICACHE|DCACHE
__NR_Linux = 4000
__NR_cacheflush = 147+ __NR_Linux
        li v0,__NR_cacheflush; syscall

        lw v0,lxlzma_retval(sp)  # return value from decompression

        lw tmp,lxlzma_sv_sp(sp)
        lw ra,lxlzma_sv_pc(sp)
/* Workaround suspected glibc bug: elf/rtld.c assumes uninit local is zero.
   2007-11-24 openembedded.org mipsel-linux 2.6.12.6/glibc 2.3.2
*/
        subu tmp,sp,tmp  # previous sp (un_alloca)
0:
        addiu sp,4
        bne sp,tmp,0b
          sw $0,-4(sp)

        jr ra
          nop

lzma_decode:  # fall into LZMA_DEC10 ("small") or LZMA_DEC20 ("fast")

section     LZMA_DEC10
#include    "lzma_d_cs.S"

section     LZMA_DEC20
#include    "lzma_d_cf.S"

section     LZMA_DEC30
        break  // FIXME
          nop

not_lzma:  // fall into next daisy chain

// vi:ts=8:et

