/*
;  lzma_d.S -- 64-bit assembly
;
;  This file is part of the UPX executable compressor.
;
;  Copyright (C) 2006-2025 Markus Franz Xaver Johannes Oberhumer
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
#define src  %arg1  /* %rdi */
#define lsrc %arg2  /* %rsi */
#define dst  %arg3  /* %rdx */
#define ldst %arg4  /* %rcx */ /* Out: actually a reference: &len_dst */
#ifndef meth  //{
#define meth %arg5l /* %r8  */
#define methb %arg5b
#endif  //}

// ELFMAINX (or amd64-expand.S/decompress:) has already done this for us:
//      pushq %rbp; push %rbx  // C callable
//      pushq ldst  // MATCH_51
//      addq src,lsrc; push lsrc  // MATCH_52 &input_eof
//      pushq dst  // MATCH_53
//      subq src,lsrc //restore the value of lsrc

#ifndef NO_METHOD_CHECK
#define M_LZMA          14
        cmpb $ M_LZMA,methb; jne not_lzma
#endif
        pushq %rbp; movq %rsp,%rbp  // we use alloca; 'leave' is in LZMA_DEC30

//LzmaDecode(  // from lzmaSDK/C/7zip/Compress/LZMA_C/LzmaDecode.h
//      %arg1= &CLzmaDecoderState,
//      %arg2= in,  %arg3l= inSize, %arg4= &inSizeProcessed,
//      %arg5= out, %arg6l= outSize, arg7@ 8+%esp/ &outSizeProcessed
//)
        movl (ldst),%arg6l  // &outSize  XXX: 4GB
        movq dst,%arg5  // outp
        movq lsrc,%arg3  // inSize
        leaq 2(src),%arg2; pushq %arg2  // MATCH_70 in; save @-8(%rbp) for size calc at eof

        movb (src),%al; decl %arg3l  // first byte, replaces LzmaDecodeProperties()
        movb %al,%cl  // cl= ((lit_context_bits + lit_pos_bits)<<3) | pos_bits
        andb $7,%al  // al= pos_bits
        shrb $3,%cl  // cl= lit_context_bits + lit_pos_bits

#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE   768
#define szSizeT 4

        movq $-LZMA_LIT_SIZE,%rbx
        shlq %cl,%rbx; movb %al,%cl  // %cl= pos_bits
// alloca{inSizeProcessed, outSizeProcessed, *_bits, CLzmaDecoderState}
        leaq -(2*szSizeT +4) - 2*LZMA_BASE_SIZE(%rsp,%rbx,2), %rbx
        andq $~0<<6,%rbx  // 64-byte align
1:
        pushq $0  // clear CLzmaDecoderState on stack
        cmpq %rbx,%rsp
        jne 1b


        pushq %rbx  // &outSizeProcessed [arg7]
        leaq 2*szSizeT(%rbx),%arg1  // &CLzmaDecoderState
        movb -1(%arg2),%cl; decl %arg3l  // second byte, replaces LzmaDecodeProperties()
                       movb %al,2(%arg1)  // store pos_bits
        movb  %cl,%al  // al= (lit_pos_bits<<4) | lit_context_bits
        shrb   $4,%cl; movb %cl,1(%arg1)  // store lit_pos_bits
        andb $0xf,%al; movb %al, (%arg1)  // store lit_context_bits
        leaq -szSizeT(%arg1),%arg4  // &inSizeProcessed

#ifdef WINDOWS_BACK
        pushq %rax  // return address slot (dummy CALL) [value ignored]
#else
        push $0x5A  // return address slot (dummy CALL) [value easy to debug]
#endif // WINDOWS_BACK

#ifndef NO_RED_ZONE

section LZMA_DEC10
#include "lzma_d_cs.S"

section LZMA_DEC20
#include "lzma_d_cf.S"

#else

section LZMA_DEC20
#include "lzma_d_cn.S"

#endif

section LZMA_DEC30
        movq -1*NBPW(%rbp),%rsi  // MATCH_70  src [after header]
#ifdef WINDOWS_BACK
        movq  2*NBPW(%rbp),%rdi  // dst  (actually an un-checked bug)
#else
        movq  1*NBPW(%rbp),%rdi  // dst
#endif
        movl szSizeT(%rbx),%ecx; addq %rcx,%rsi  //  inSizeProcessed
        movl        (%rbx),%edx; addq %rdx,%rdi  // outSizeProcessed
        leave  //  %rsp = %rbp;  %rbp = * %rsp ++;  "enter" is in LZMA_ELF00

#ifdef WINDOWS_BACK  //{  Must match stub/amd64-win64.pe.h of upx-v4.2.4.
    // amd64-win64.pe.S has unconditional "#define NO_METHOD_CHECK"
    // because p_w64pe_amd64.cpp assumes only one method, and generates it;
    // thus there is no need to check the method, nor to recover from a mismatch.
    // In such a case LZMA_DEC30 ends with the [inner] 'leave' above, and
    // falls into section PEMAIN20, which immediately has an [outer] 'leave'.
#else  //}{  ndef WINDOWS_BACK
        jmp eof_lzma  # lzma de-compression is done
    #ifndef NO_METHOD_CHECK  //{
    not_lzma:  # recover from not matching M_LZMA
        push %rdi; pop %rsi  # src = arg1
        # fall into next daisy-chain method
    #endif  //}
#endif  //}

// vi:ts=8:et

