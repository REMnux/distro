/*
;  lzma_d.S -- RiscV 64-bit assembly
;
;  This file is part of the UPX executable compressor.
;
;  Copyright (C) Markus Franz Xaver Johannes Oberhumer
;  All Rights Reserved.
;
;  UPX and the UCL library are free software; you can redistribute them
;  and/or modify them under the terms of the GNU General Public License as
;  published by the Free Software Foundation; either version 2 of
;  the License, or (at your option) any later version.
;
;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.
;
;  You should have received a copy of the GNU General Public License
;  along with this program; see the file COPYING.
;  If not, write to the Free Software Foundation, Inc.,
;  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;
;  Markus F.X.J. Oberhumer
;  <markus@oberhumer.com>
;  http://www.oberhumer.com/opensource/upx/
;
*/

NBPW= 8
#define section .section

section LZMA_ELF00
//decompress:  // (uchar const *src, size_t lsrc, uchar *dst, u32 &ldst, uint method)
/* Arguments according to calling convention */
#define lzsrc  arg1
#define lzlsrc arg2
#define lzdst  arg3
#define lzldst arg4  /* Out: actually a reference: &len_dst */
#define lzmeth arg5

// ELFMAINX (or amd64-expand.S/f_expand:) has already setup F_EOFDST, F_EOFSRC:
//    PUSH4 s0,s1,zero,zero  // MATCH_93  ABI callee saved; MATCH_92 F_EOFSRC, F_EOFDST
//    PUSH4 lzsrc,lzdst,llzdst,ra  // MATCH_95 params to unfilter and sync_cache
F_FRAME= 8*NBPW
F_EOFDST=7*NBPW
F_EOFSRC=6*NBPW; F_ENTR= F_EOFSRC; F_PMASK= F_EOFSRC

#ifndef NO_METHOD_CHECK
#define M_LZMA          14
        addi lzmeth,lzmeth,-M_LZMA; jne not_lzma
#undef lzmeth
#endif
	mv s0,sp  // local frame

//LzmaDecode(  // from lzmaSDK/C/7zip/Compress/LZMA_C/LzmaDecode.h
//  %arg1= &CLzmaDecoderState,
//  %arg2= in,  %arg3l= inSize, %arg4= &inSizeProcessed,
//  %arg5= out, %arg6l= outSize, arg7@ 8+%esp/ &outSizeProcessed
//)
        ld arg6,0(lzldst)  // outSize
	mv arg5,lzdst  // outp
        mv arg3,lzlsrc  // inSize
	addi arg2,lzsrc,2  // in (beyond lzma header)

#define arg7 x16
#define lzhdrb  t2
#define lzhpos  t1
#define lztmp   t0
	lbu lzhdrb,0(lzsrc); addi arg3,arg3,-1  // first byte, replaces LzmaDecodeProperties()
        // lzhdrb= ((lit_context_bits + lit_pos_bits)<<3) | pos_bits
        andi lzhpos,lzhdrb,7  // pos_bits
        srli lzhdrb,lzhdrb,3  // lit_context_bits + lit_pos_bits

#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE   768
#define szSizeT NBPW

        li  s1,LZMA_LIT_SIZE
        sll s1,s1,lzhdrb  // by (lit_context_bits + lit_pos_bits)
// alloca{inSizeProcessed, outSizeProcessed, *_bits, CLzmaDecoderState}
	slli s1,s1,1  // sizeof(unsigned short)
	li lztmp,2*LZMA_BASE_SIZE + 2*szSizeT + NBPW
	add s1,s1,lztmp
	sub s1,sp,s1; andi s1,s1,~0<<6  // 64-byte align
	mv sp,s1
0: // clear CLzmaDecoderState on stack
	sd zero,0(s1); sd zero,NBPW(s1); addi s1,s1,2*NBPW; bne s1,s0,0b

        mv arg7,sp  // &outSizeProcessed
	addi arg1,sp,2*szSizeT  // &CLzmaDecoderState
	                     sb lzhpos,2(arg1)  // store pos_bits
	lbu lztmp,-1(arg2); addi arg3,arg3,-1  // second byte, replaces LzmaDecodeProperties()
	// lztmp= (lit_pos_bits<<4) | lit_context_bits
        srl lztmp,lztmp,4;    sb lztmp,1(arg1)  // store lit_pos_bits
	lbu lztmp,-1(arg2)
	andi lztmp,lztmp,0xf; sb lztmp,0(arg1)  // store lit_context_bits
	addi arg4,arg1,-szSizeT  // &inSizeProcessed

	jal lzma_code     # a0= rv (0 ==> success)
	ld a1,0*NBPW(sp)  # outSizeProcessed
	ld a2,1*NBPW(sp)  #  inSizeProcessed

	mv sp,s0  // de-alloca()
	j eof_lzma

lzma_code:

section LZMA_DEC20
#include "lzma_d_cn.S"

section LZMA_DEC30
	# empty
not_lzma:   # fall into next daisy-chain lzmethod

// vi:ts=8:et
