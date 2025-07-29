/*  arm.v4a-linux.elf-so_entry.S -- Linux DT_INIT & decompressor (Elf shared lib)
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

NBPW= 4
//#define ARM_OLDABI 1
#define ARMEL_EABI4 1
#include "arch/arm/v5a/macros.S"
#define call bl

#define DEBUG 0
#define bkpt .long 0xe7f001f0  /* reserved instr; Linux GNU eabi breakpoint */
#define bkpt_th .short 0xde01  /* reserved instr; Linux GNU eabi breakpoint */

// As of 2023-02-04, "gcc (Debian 10.2.1-6) 10.2.1 20210110" assembles 0xbe10 for:
//      asm("bkpt #0x10");
// and a RaspberryPi v2 (32-bit only) running Linux executes as an infinite loop
// with kernel message spewing:
//       Unhandled prefetch abort: breakpoint debug exception (0x002)
// That's running with "uname -a" that says
//      Linux <hostname> 5.10.0-20-armmp #1 SMP Debian 5.10.158-2 (2022-12-13) armv7l GNU/Linux

sz_Elf32_Ehdr = 13*NBPW
sz_Elf32_Phdr =  8*NBPW

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8
sz_l_info= 12
sz_p_info= 12

PROT_READ=  1
PROT_WRITE= 2
PROT_EXEC=  4

MAP_PRIVATE= 2
MAP_FIXED=     0x10
MAP_ANONYMOUS= 0x20

PAGE_SHIFT= 12
PAGE_MASK=  (~0<<PAGE_SHIFT)
PAGE_SIZE= -PAGE_MASK

__NR_open=       5 + __NR_SYSCALL_BASE
  AT_FDCWD= -100
  RD_ONLY= 0
__NR_close=      6 + __NR_SYSCALL_BASE
__NR_exit =      1 + __NR_SYSCALL_BASE
__NR_memfd_create= 0x181 + __NR_SYSCALL_BASE  // 385
__NR_mmap64 = 0xc0 + __NR_SYSCALL_BASE
__NR_mprotect =125 + __NR_SYSCALL_BASE
__NR_munmap =   91 + __NR_SYSCALL_BASE
__NR_write =     4 + __NR_SYSCALL_BASE

__NR_SYSCALL_BASE = 0

__NR_close=     6 + __NR_SYSCALL_BASE
__NR_exit=      1 + __NR_SYSCALL_BASE
__NR_fdatasync=148 + __NR_SYSCALL_BASE
__NR_fsync=   118 + __NR_SYSCALL_BASE
__NR_ftruncate=93 + __NR_SYSCALL_BASE
__NR_getpid=   20 + __NR_SYSCALL_BASE
__NR_lseek=    19 + __NR_SYSCALL_BASE
__NR_memfd_create= 385 + __NR_SYSCALL_BASE
__NR_mkdir=    39 + __NR_SYSCALL_BASE
__NR_mmap2=   192 + __NR_SYSCALL_BASE
__NR_mprotect=125 + __NR_SYSCALL_BASE
__NR_msync=   144 + __NR_SYSCALL_BASE  // 0x90
__NR_open=      5 + __NR_SYSCALL_BASE
__NR_openat=  322 + __NR_SYSCALL_BASE
__NR_read=      3 + __NR_SYSCALL_BASE
__NR_stat=    106 + __NR_SYSCALL_BASE
__NR_uname=   122 + __NR_SYSCALL_BASE
__NR_unlink=   10 + __NR_SYSCALL_BASE
__NR_write=     4 + __NR_SYSCALL_BASE

__ARM_NR_BASE  = 0xf0000 + __NR_SYSCALL_BASE
__ARM_NR_cacheflush =  2 + __ARM_NR_BASE

arg1 .req r0
arg2 .req r1
arg3 .req r2
arg4 .req r3
arg5 .req r4
arg6 .req r5

esi .req r1
eax .req r4

#define SP(d) sp,#4*(_-d)  /* stack addressing mode */

.macro thumb_sys7t N
#if defined(ARMEL_EABI4)
        mov r7,#\N
        swi 0
#elif defined(ARM_OLDABI)
        blx x\N
#else
        error \N  // ARM_OLDABI, ARMEL_EABI4, ARMEL_DARWIN ?
#endif

.endm

.macro call4 label // ARM mode; not THUMB mode
        .balign 4
        bl \label
.endm

.macro blx reg  // armv4a only
        mov lr,pc  // .+2*NBPW
        b \reg  // reg must not be 'lr'
.endm

.macro push_ reg
        str reg,[sp,#-4]!
_= 1+_  // one more word on stack
.endm

.macro pop_ reg
        pop {\reg}
_=-1+_  // one less word on stack
.endm

  section ELFMAINX
//  .long offset(b_info)|(asl_delta>>12)  src for f_exp  // FIXME: not true?
//SO_INFO:
//  .long offset(.)  // detect relocation
//  .long offset(user DT_INIT)
//  .long offset(xct_off)  // lowest executable instr
//  .long offset(dst for f_exp)

        //.arch armv7-a
        //.syntax unified
        .type _start,%function
        .balign 4
_start: .globl _start
        nop
#if 0|DEBUG  //{
        bkpt  // DEBUG
#endif  //}
        // argc,argv,envp, r3 convenience, r4-r7 callee-saved, lr ret_addr
        stmfd sp!,{r0,r1,r2, r3, r4,r5,r6,r7, lr}  // MATCH_99

        sub sp,sp,#F_ARGC  // space for ADRU, LENU, PMASK
F_ADRU= 0 * NBPW
F_LENU= 1 * NBPW
F_PMASK=2 * NBPW
F_ARGC= 3 * NBPW

        call4 L70
L70_ret:
    foldi   .req lr  // &fold_info
    mfd     .req r7
    rPMASK  .req r6  // PAGE_MASK

        ldr r0,[foldi,#sz_unc]
        str r0,[sp,#F_LENU]
        ldr r7,[foldi,#sz_cpr]  // srclen
        add r4,foldi,#sz_b_info  // src
    .unreq foldi

        mov arg3,#0  // pathname
        mov arg2,r0  // sz_unc
        mov arg1,#0  // any page address
        call upx_mmap_and_fd
        add arg4,sp,#F_LENU  // &dstlen
        mov arg3,r0,lsr #12
        mov arg3,arg3,lsl #12  // dst for decompress
        str arg3,[sp,#F_ADRU]
        mov arg2,r7  // srclen
          sub mfd,r0,arg3
          sub mfd,mfd,#1  // mfd
        mov arg1,r4  // src
        call f_decompress; cmp r0,#0; beq 0f; bkpt; 0:

        ldr arg3,[sp,#F_LENU]
        ldr arg2,[sp,#F_ADRU]
        mov arg1,mfd
        str rPMASK,[arg2,#0]  // forward the PAGE_MASK
        call write; cmp r0,arg3; beq 0f; bkpt; 0:

        mov arg6,#0  // beginning of file
        mov arg5,mfd
        mov arg4,#MAP_PRIVATE|MAP_FIXED  // modes
        mov arg3,#PROT_READ|PROT_EXEC  // prot
        ldr arg2,[sp,#F_LENU]
        ldr arg1,[sp,#F_ADRU]  // addr
        do_sys __NR_mmap2; ldr arg3,[sp,#F_ADRU]; cmp r0,arg3; beq 0f; bkpt; 0:

        mov arg1,mfd
    .unreq mfd
        call close

        add arg2,sp,#F_ARGC
        adr arg1,_start -4 *NBPW  // &SO_INFO
        ldr arg3,[sp, #F_ADRU]
        add pc,arg3,#3*NBPW  // invoke de-compressed code

f_decompress:
#undef LINUX_ARM_CACHEFLUSH  /* handled by write()+mmap() */
#include "arch/arm/v4a/nrv2b_d8.S"

        src .req r0
        dst .req r2
        tmp .req r3
//eof_n2b: .globl eof_n2b
// end of a compressed extent
        POP {tmp}  // &input_eof
        mov r0,src; SUB2 r0,tmp  // src -= eof;  // return 0: good; else: bad
        POP {tmp}  // original dst
        POP {r1}; SUB2 dst,tmp  // dst -= original dst
        POP {tmp}; str dst,[tmp]  // actual length used at dst  XXX: 4GB
        ret
//%esp:
//  MATCH_04  ptr unfolded_code
//  MATCH_10  len unfolded_code
//  MATCH_00  argc
//  MATCH_01  argv
//  MATCH_07  envp

// get_page_mask should never be called by so_entry, because the 1st arg
// (the pointer) to upx_mmap_and_fd is 0.  But in the general case
// there must be a get_page_mask subroutine.  Return something plausible.
get_page_mask: .globl get_page_mask
        mvn r0,#0
        mov r0,r0,lsl #12
        ret

upx_mmap_and_fd: .globl upx_mmap_and_fd
        // UMF_LINX or UMF_ANDROID goes here

// IDENTSTR goes here

  section ELFMAINZ
get_upxfn_path: .globl get_upxfn_path  // char * (*)(void)
        mov r0,#0  // persistence not desired
        ret

memcpy: .globl memcpy  // void *memcpy(void *dst, void const *src, size_t len)
        cmp r2,#0; beq 9f
        mov r12,r0  // original dst
0:
        ldrb r3,[r1],#1; subs  r2,r2,#1
        strb r3,[r0],#1; bne 0b
9:
        mov r0,r12  // return original dst
        ret

memset: .globl memset  // (dst, val, n)
        cmp r2,#0; beq 9f
        mov r12,r0  // original dst
0:
        strb r1,[r0],#1
        subs r2,r2,#1
        bne 0b
9:
        mov r0,r12  // return original dst
        ret

mempcpy: .globl mempcpy  // (dst, src, n)
        cmp r2,#0; beq 9f
0:
        ldrb r3,[r1],#1; subs r2,r2,#1
        strb r3,[r0],#1; bne 0b
9:
        ret  // updated dst

// These Linux system calls are called from upxfd_android.c
// in order to work around problems with memfd_create and ftruncate on Android.
// Because called from C, then r7 is live; cannot use do_sys7t.
.globl memfd_create; memfd_create: do_sys2 __NR_memfd_create; ret
.globl close;     close:     do_sys __NR_close; ret
.globl exit;      exit:      do_sys __NR_exit; ret
.globl fdatasync; fdatasync: do_sys __NR_fdatasync; ret
.globl fsync;     fsync:     do_sys __NR_fsync; ret
.globl ftruncate; ftruncate: do_sys __NR_ftruncate; ret
.globl getpid;    getpid:    do_sys __NR_getpid; ret
.globl lseek;     lseek:     do_sys __NR_lseek; ret
.globl mkdir;     mkdir:     do_sys __NR_mkdir; ret
.globl open;      open:      do_sys __NR_open; ret
.globl openat;    openat:    do_sys2 __NR_openat; ret
.globl read;      read:      do_sys __NR_read; ret
.globl stat;      stat:      do_sys __NR_stat; ret
.globl uname;     uname:     do_sys __NR_uname; ret
.globl unlink;    unlink:    do_sys __NR_unlink; ret
.globl write;     write:     do_sys __NR_write; ret

        .globl my_bkpt
my_bkpt:
        bkpt  // my_bkpt
        ret

// __NR_oldmmap gets ENOSYS!  Must use __NR_mmap2 with all args in registers
// Called from C (5th and 6th arg on stack), so must preserve r4 and r5
mmap: .globl mmap
        stmdb sp!,{r4,r5,lr}  // called from C: only 4 args in registers
        ldr arg6,[sp,#4*NBPW]
        ldr arg5,[sp,#3*NBPW]
        mov arg6,arg6,lsr #12  @ FIXME?  convert to page offset in file
mmap_do: // sp: saved r4,r5,lr
        bic r12,arg1,rPMASK  // lo frag
        sub arg1,arg1,r12  // page align lo end
        add arg2,arg2,r12
        do_sys __NR_mmap2
        ldmia sp!,{r4,r5,pc}

psa:    .asciz "/proc/self/auxv"; .balign 4
L70:
BUFLEN= 512
mfd .req r5
        sub sp,sp,#BUFLEN
        mov r4,lr
        mov rPMASK,#~0; mov rPMASK,rPMASK,lsl #12  // default PAGE_MASK
        mov r0,#AT_FDCWD
        adr r1,psa
        mov r2,#0
        call openat; mov mfd,r0; tst r0,r0; bmi no_psa
        mov r2,#BUFLEN
        mov r1,sp
        mov r0,mfd
        call read; tst r0,r0; bmi no_psa1
        mov r1,sp
0:
        ldr r2,[r1],#2*NBPW
AT_PAGESZ= 6
        subs r2,r2,#AT_PAGESZ; beq 9f
        subs r0,r0,#2*NBPW; beq no_psa1; b 0b
9:
        ldr rPMASK,[r1,#-NBPW]
        sub rPMASK,r2,rPMASK
no_psa1:
        mov r0,mfd; call close
.unreq mfd
no_psa:
        add sp,sp,#BUFLEN
        str rPMASK,[sp,#F_PMASK]

        call4 L70_ret
fold_info:
//  b_info (sz_unc, sz_cpr, method) of folded code (C-language, etc.)

/* vim:set ts=8 sw=8 et: */
