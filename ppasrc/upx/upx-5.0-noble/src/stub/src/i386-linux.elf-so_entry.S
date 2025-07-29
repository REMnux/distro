/*  i386-linux.elf-so_entry.S -- Linux DT_INIT & decompressor (Elf shared lib)
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) 1996-2021 Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) 1996-2021 Laszlo Molnar
*  Copyright (C) 2000-2025 John F. Reiser
*  All Rights Reserved.
*
*  UPX and the UCL library are free software; you can redistribute them
*  and/or modify them under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of
*  the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; see the file COPYING.
*  If not, write to the Free Software Foundation, Inc.,
*  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*
*  Markus F.X.J. Oberhumer              Laszlo Molnar
*  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
*
*  John F. Reiser
*  <jreiser@users.sourceforge.net>
*/

//#include "arch/amd64/macros.S"
//#include "arch/amd64/regs.h"
#define section .section

NBPW= 4

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8

PROT_READ=  1
PROT_WRITE= 2
PROT_EXEC=  4

MAP_PRIVATE= 2
MAP_FIXED=     0x10
MAP_ANONYMOUS= 0x20

__NR_close= 6
__NR_exit=  1
__NR_memfd_create= 0x164 // 356
__NR_mkdir=    39
__NR_mprotect=125
__NR_munmap=   91
__NR_oldmmap=  90  // old mmap: %ebx -> args[6]
__NR_read=    3
__NR_stat=  106
__NR_uname= 122
__NR_write=   4

PAGE_SHIFT= 12
PAGE_MASK= (~0<<PAGE_SHIFT)
PAGE_SIZE= -PAGE_MASK
AT_PAGESZ= 6
NAME_MAX=  255  // # chars in file name; linux/include/uapi/linux/limits.h

M_NRV2B_LE32=2  // ../conf.h
M_NRV2D_LE32=5
M_NRV2E_LE32=8

// syscall arguments
#define arg5 edi
#define arg4 esi
#define arg3 edx
#define arg2 ecx
#define arg1 ebx

/* Arguments to decompress() */
#define src  %esi
#define lsrc %ecx
#define dst  %edi
//#define ldst %edx  /* Out: actually a reference: &len_dst */

// Written by PackLinuxElf::pack3():
//  .long offset(.)  // detect relocation
//  .long offset(user DT_INIT)
//  .long offset(escape_hatch)
//  .long offset({l_info; p_info; b_info; compressed data})
  section ELFMAINX
_start:  // C-called: %esp: ret_addr,argc,argv,envp; must save %ebx,%esi,%edi,%ebp
    //  int3  // DEBUG i386 so_entry.S
    pusha  // MATCH_03
    call L70  // MATCH_08  push $&getbit
L70ret:

/* Working registers for local NRV2B */
#define off  %eax  /* XXX: 2GB */
#define bits %ebx
#define len  %ecx  /* XXX: 2GB */
#define disp %ebp

#define GETBIT call *%edx
#define jnextb0 GETBIT; jnc
#define jnextb1 GETBIT; jc

/* rotate next bit (now in Carry) into bottom bit of reg */
#define getnextb(reg) GETBIT; adcl reg,reg

getbit:
        .byte 0xf3,0x0f,0x1e,0xfb  // endbr32
        addl bits,bits; jz refill  // Carry= next bit
        rep; ret  // rep: stop instruction pipeline (spend 1 byte for speed)
refill:
        mov (%esi),bits; sub $-NBPW,%esi  // next 32 bits; set Carry
        adc bits,bits  // LSB= 1 (CarryIn); CarryOut= next bit
        ret  // infrequent (1/32)

#define old_sp %ebp
#define foldi  %esi
L20:
        pop foldi  // MATCH_09  &fold_info
        cmpw $M_NRV2B_LE32|(0<<8),b_method(foldi); je 0f; hlt; 0:  // check method and filter

        movl /*sz_unc*/(foldi),%ecx
LEN_PATH= 1+ 11 + NAME_MAX + 13  // "/data/data/$APP_NAME/cache/upxAAA"
        lea LEN_PATH(%ecx),%ecx; push %ecx  // P_10 F_LENU
        push $0x5A  // P_11 %F_ADRU,F_LENU
        push %edi  // P_12  PMASK,%F_ADRU,F_LENU
        lea _start - 4*NBPW - L70ret(%edx),%eax
        push %eax  // P_13 &so_info,PMASK,%F_ADRU,F_LENU
        push %edx  // P_14 &refill,so_info,PMASK,%F_ADRU,F_LENU
        push foldi  // P_14  foldi,&refill,&so_info,PMASK,%F_ADRU,F_LENU
    mov %esp,old_sp
        sub $LEN_PATH,%esp; and $-2*NBPW,%esp; push $0  // pathname[0]= '\0';
        mov %esp,%edi

        push %edi  // arg3  pathname; pathname[0] = '\0'
        push %ecx  // arg2  F_LENU
        push $0    // arg1  any page address
        call upx_mmap_and_fd; add $3*NBPW,%esp  // %eax= page_addr | (1+fd)
        test $(1<<11),%eax; jz 0f; hlt; 0: // fd "negative" ==> failure
#define mfd    %edx
        mov %eax,mfd
        shrl $12,%eax
        shll $12,%eax  // page addr
        sub %eax,mfd; dec mfd


        mov (old_sp),foldi
        mov sz_unc(foldi),%edi
        add %eax,%edi
        mov %edi,2*NBPW(%eax)  // forward upxfn_path  FIXME: after decompress ?
        mov %esp,%esi
        mov $LEN_PATH,%ecx
        rep movsb
    mov old_sp,%esp  // foldi,&refill,&so_info,PMASK,%F_ADRU,F_LENU
#undef old_sp
        mov %eax,4*NBPW(%esp)  // F_ADRU

        pop foldi  // P_14  &refill,&so_info,PMASK,F_ADRU,F_LENU
        push mfd  // P_15  mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU
#undef mfd
        push sz_unc(foldi)  // P_16 sz_unc,mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU
        push %esp  // P_17  &dst_len,sz_unc,mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU
        mov sz_cpr(foldi),lsrc
        lea sz_b_info(foldi),src
#undef foldi
        mov %eax,dst

// This is nrv2b_d32, inlined and optimized for small space (about 160 bytes).
// The task is to de-compress the folded pieces for shared library init:
// the de-compressor(s) of the PT_LOAD pieces, and the C-code supervisor
// which adjusts the placement and mapping of the address space.
// The output length is a couple KB for NRV, a few KB for Lzma, 64KB for Zstd.
// This is motivated by the possibility of using multiple de-compressors
// depending on the characteristics of each PT_LOAD, and by the increased size
// and compressability of C-coded de-compressors for Lzma and Zstd
// in contrast to the simple and small assembly-coded NRV.

decompress:  // inlined: (uchar const *src, uint len, uchar *dst /*, u32 &ldst, uint method */)
        add src,lsrc; push lsrc  // P_20 eof,&dst_len,sz_unc,mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU

//%esp:
//  MATCH_05  &input_eof
//  &dst_len (==> sz_unc in next word)
//  sz_unc
//  mfd
//  &refill
//  MATCH_14  &so_info
//  PMASK
//  P_11  F_ADRU
//  MATCH_10  F_LENU
//  MATCH_03  pusha regs {%edi,%esi,%ebp,%esp,%ebx,%edx,%ecx,%eax}
//            ret_addr
//  MATCH_00  argc
//  MATCH_01  argv
//  MATCH_07  envp

        mov 4*NBPW(%esp),%edx  // &refill
        xor bits,bits  // empty; force refill
        xor len,len  // create loop invariant
        or $~0,disp  // -1: initial dispacement
        cld  // paranoia
        .byte 0xa8  // "testb $... ,%al" ==> "jmp top_n2b"
lit_n2b:
        movsb  // *dst++ = *src++;
top_n2b:
        jnextb1 lit_n2b
        lea 1(len),off  # [len= 0] off= 1
offmore_n2b:
        getnextb(off)
        jnextb0 offmore_n2b

        sub $ 3,off; jc len_n2b  # use previous offset
        shl $ 8,off; lodsb  # off is %eax, so 'lodsb' is "off |= *src++;"
        xor $~0,off; jz eof_n2b
        mov off,disp  # XXX: 2GB
len_n2b:
        lea 1(len),off  # [len= 0] off= 1
        getnextb(len); getnextb(len)  # two bits; cc set on result
        jnz gotlen_n2b  # raw 1,2,3 ==> 2,3,4
        mov off,len  # len= 1, the msb
        add $3-1,off  # raw 2.. ==> 5..
lenmore_n2b:
        getnextb(len)
        jnextb0 lenmore_n2b
gotlen_n2b:
        cmp $-0xd00,disp  # XXX: 2GB
        adc off,len  # len += off + (disp < -0xd00)
        push %esi  // MATCH_06
          lea (%edi,disp),%esi
          rep; movsb
        pop %esi  // MATCH_06
        jmp top_n2b

eof_n2b:
        pop %ecx  // MATCH_05  &input_eof; &dst_len,sz_unc,mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU
        cmp %ecx,%esi; je 0f; hlt; 0:  // test for ending in correct place
        pop %ecx  // toss &dst_len; sz_unc,mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU

        // Forward data to unfolded segment
        mov 5*NBPW(%esp),%edi  // F_ADRU
        mov 4*NBPW(%esp),%eax; mov %eax,      (%edi)  // fold.PAGE_MASK
        pop %eax;              mov %eax,2*NBPW(%edi)  // fold.upx_fn_path  sz_unc
                    // mfd,&refill,&so_info,PMASK,F_ADRU,F_LENU

        mov 5*NBPW(%esp),%arg3  // F_LENU
        mov %edi,%arg2  // F_ADRU
        pop %arg1  // mfd; &refill,&so_info,PMASK,F_ADRU,F_LENU
        pop %eax  // toss &refill; &so_info,PMASK,F_ADRU,F_LENU
          push $0  // arg6
          push %arg1  // arg5 mfd
        push $__NR_write; pop %eax; int $0x80

        push $MAP_FIXED|MAP_PRIVATE  // arg4
        push $PROT_READ|PROT_EXEC  // arg3
        push %arg3  // arg2  F_LENU
        push %edi   // arg1: F_ADRU
        mov %esp,%ebx; push $__NR_oldmmap; pop %eax; int $0x80
          mov 4*NBPW(%esp),%arg1  // mfd
        add $6*NBPW,%esp

        push $__NR_close; pop %eax; int $0x80

        add $3*NBPW,%edi
        jmp *%edi  // %esp/ &so_info,PMASK,F_ADRU,F_LENU
// %esp:
//  MATCH_14  &so_info
//            PMASK
//            ADRU
//            LENU
//  MATCH_03  pusha regs {%edi,%esi,%ebp,%esp,%ebx,%edx,%ecx,%eax}
//            ret_addr
//  MATCH_00  argc
//  MATCH_01  argv
//  MATCH_07  envp


old_mmap:  // oldmmap: ebx -> 6 arguments; remove arguments on return
        lea 4(%esp),%ebx
        push $__NR_oldmmap; pop %eax; int $0x80
        cmp $PAGE_MASK,%eax; jb 0f; hlt; 0:
        ret $6*4

// get_page_mask should never be called by so_entry, because the 1st arg
// (the pointer) to upx_mmap_and_fd is 0.  But in the general case
// there must be a get_page_mask subroutine.  Return something plausible.
get_page_mask: .globl get_page_mask
        mov $-(1<<12),%eax  // 4KB page size
        ret

        .balign 4
upx_mmap_and_fd:
// section UMF_LINUX or UMF_ANDROID goes here

// IDENTSTR goes here

  section ELFMAINZ
get_upxfn_path: .globl get_upxfn_path  // char * (*)(void)
        xor %eax,%eax  // persistence not desired
        ret

stat: .globl stat
        xchg %ebx,NBPW(%esp)
        mov 2*NBPW(%esp),%ecx
        movb $__NR_stat,%al; call sys_check_al
        mov NBPW(%esp),%ebx
        ret

uname: .globl uname
        push %ebp; mov %esp,%ebp; push %ebx
        mov 2*NBPW(%ebp),%ebx
        movb $__NR_uname,%al; call sys_check_al
        pop %ebx; pop %ebp
        ret

mkdir: .globl mkdir
        push %ebp; mov %esp,%ebp; push %ebx
        mov 2*NBPW(%ebp),%ebx
        mov 3*NBPW(%ebp),%ecx
        movb $__NR_mkdir,%al; call sys_check_al
        pop %ebx; pop %ebp
        ret

memset: .globl memset  // (dst, val, n)
        push %ebp; mov %esp,%ebp
        push %edi
        mov (2+ 2)*NBPW(%ebp),%ecx
        mov (2+ 1)*NBPW(%ebp),%eax
        mov (2+ 0)*NBPW(%ebp),%edi
        rep stosb
        pop %edi
        pop %ebp
        ret

mempcpy: .globl mempcpy  // (dst, src, n)
        push %ebp; mov %esp,%ebp
        push %edi; push %esi
        mov (2+ 2)*NBPW(%ebp),%ecx
        mov (2+ 1)*NBPW(%ebp),%esi
        mov (2+ 0)*NBPW(%ebp),%edi
        rep movsb
        mov %edi,%eax
        pop %esi; pop %edi; pop %ebp
        ret

        .globl my_bkpt
my_bkpt:
        int3  // my_bkpt
        ret

// C-callable, so do NOT remove arguments as part of return
mmap: .globl mmap  // oldmmap: ebx -> 6 arguments
        push %ebx  // save register
        lea 2*NBPW(%esp),%ebx
        movb $__NR_oldmmap,%al; call sys_check_al
        pop %ebx  // restore register
        ret

sys_check_al:
        movzbl %al,%eax
sys_check:
        push %eax  // save __NR_ for debug
        int $0x80
        pop %edx  // recover __NR_ for debug
        cmp $-0x1000,%eax; jae 0f; ret; 0:
        hlt

L70:
// Get PAGE_MASK from AT_PAGESZ in /proc/self/auxv
BUFLEN= 512
FD_CWD = -100
__NR_openat= 295
        sub $BUFLEN,%esp
        xor %arg3,%arg3  // O_RDONLY
        call 0f; .asciz "/proc/self/auxv"; 0: pop %arg2
        push $FD_CWD; pop %arg1
        mov $__NR_openat,%eax; int $0x80
          test %eax,%eax; jl no_psa
#define mfd %ebp
        mov %eax,mfd  // fd
        mov $BUFLEN,%arg3
        mov %esp,%arg2  // buf
        mov %eax,%arg1  // fd
        push $__NR_read; pop %eax; int $0x80; test %eax,%eax; jl no_psa

        mov %eax,%ecx  // len
        mov %esp,%esi  // src
0:
        lodsl; test %eax,%eax; jz no_psa
        cmp $AT_PAGESZ,%eax
        lodsl; je 6f
        sub $2*NBPW,%ecx; jnz 0b
no_psa:
        movl $0x1000,%eax  // default PAGE_SIZE
6:
        neg %eax  // PAGE_MASK
        add $BUFLEN,%esp
        push %eax  // PAGE_MASK
        mov mfd,%arg1; push $__NR_close; pop %eax; int $0x80
#undef mfd
        pop %edi  // PAGE_MASK
        pop %edx  // &getbit  (also L70ret)
        call L20  // MATCH_09  push $&fold_info
fold_info:
//  b_info (sz_unc, sz_cpr, method) of folded code (C-language, etc.)

/* vim:set ts=8 sw=8 et: */
