@  arm-linux.elf-so_fold.S -- linkage to C code to process Elf shared library
@
@  This file is part of the UPX executable compressor.
@
@  Copyright (C) 2000-2025 John F. Reiser
@  All Rights Reserved.
@
@  UPX and the UCL library are free software; you can redistribute them
@  and/or modify them under the terms of the GNU General Public License as
@  published by the Free Software Foundation; either version 2 of
@  the License, or (at your option) any later version.
@
@  This program is distributed in the hope that it will be useful,
@  but WITHOUT ANY WARRANTY; without even the implied warranty of
@  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
@  GNU General Public License for more details.
@
@  You should have received a copy of the GNU General Public License
@  along with this program; see the file COPYING.
@  If not, write to the Free Software Foundation, Inc.,
@  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
@
@  Markus F.X.J. Oberhumer              Laszlo Molnar
@  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
@
@  John F. Reiser
@  <jreiser@users.sourceforge.net>
@

#define ARM_OLDABI 1
#include "arch/arm/v4a/macros.S"
#include "MAX_ELF_HDR.S"
__NR_SYSCALL_BASE = 0
__ARM_NR_BASE= 0xf0000 + __NR_SYSCALL_BASE
__ARM_NR_cacheflush = 2 + __ARM_NR_BASE
NBPW= 4

sz_Elf32_Ehdr = 13*4
sz_Elf32_Phdr =  8*4
p_vaddr= 4+4
sz_l_info = 12
sz_p_info = 12
sz_b_info = 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8

MAP_ANONYMOUS= 0x20
MAP_PRIVATE=   0x02
MAP_FIXED=     0x10

PROT_READ=     0x1
PROT_WRITE=    0x2
PROT_EXEC=     0x4

PF_X= (1 << 0)  /* Segment is executable */
PF_W= (1 << 1)  /* Segment is writable */
PF_R= (1 << 2)  /* Segment is readable */

O_RDONLY=       0

PAGE_SHIFT= 12
PAGE_SIZE = -(~0<<PAGE_SHIFT)
PATHMAX=  4096

PATH_MAX= 4096

#ifndef DEBUG  /*{*/
#define DEBUG 0
#define TRACE_REGS r0-r12,r14,r15
#endif  /*}*/

#define OVERHEAD 2048
#define call bl

mflg_data: .int MAP_PRIVATE|MAP_ANONYMOUS  @ overwritten for QNX vs Linux

// %esp:
//   MATCH_13  ptr unfolded_code; for escape hatch
//   MATCH_12  len unfolded code; for escape hatch
//             PAGE_MASK
//   MATCH_99  9 saved registers {r0= argc, r1= argv, r2= envp, r3-r7, lr)

F_ADRU=  0 * NBPW
F_LENU=  1 * NBPW
F_PMASK= 2 * NBPW  // extra copy?

  .globl upx_so_main  // in arm.v?a-linux.elf-so_main.c

  section SO_HEAD
ZERO:
PAGE_MASK: .word 0xfffff000  // default
qflg_data: .word 0  // QNX vs Linux: MAP_PRIVATE | MAP_ANONYMOUS
upxfn_path:.word 0  // displacement from "zero"

fold_begin: .globl fold
        b L05

get_page_mask: .globl get_page_mask
        ldr r0,PAGE_MASK
        ret

get_upxfn_path: .globl get_upxfn_path  // char * (*)(void)
    adr r1,ZERO
    ldr r0,[r1,#1*NBPW]  // offset(upxfn_path)
    cmp r0,#0; beq 1f  // nullptr
    add r0,r0,r1  // &path
1:
    ret

arg6 .req r5
arg5 .req r4
arg4 .req r3
arg3 .req r2
arg2 .req r1
arg1 .req r0

// Sometimes Linux enforces page-aligned address
Pmap: .globl Pmap
        ldr r12,PAGE_MASK
        bic r12,arg1,r12
        sub arg1,arg1,r12
        add arg2,arg2,r12
        b mmap

Punmap: .globl Punmap
        ldr r12,PAGE_MASK
        bic r12,arg1,r12
        sub arg1,arg1,r12
        add arg2,arg2,r12
        b munmap

Pprotect: .globl Pprotect
        ldr r12,PAGE_MASK
        bic r12,arg1,r12
        sub arg1,arg1,r12
        add arg2,arg2,r12
        b mprotect

Psync: .globl Psync
        ldr r12,PAGE_MASK
        bic r12,arg1,r12
        sub arg1,arg1,r12
        add arg2,arg2,r12

        stmdb sp!,{r0,r1,r2}  // lo, len, ??
        add r1,r1,r0  // hi
        mov r2,#0  // might be CSSELR_DCACHE from linux/arch/arm/include/asm/cachetype.h
        do_sys2 __ARM_NR_cacheflush
        ldmia sp!,{r0,r1,r2}

        b msync

L05:
    sub sp,sp,#MAX_ELF_HDR_32; mov arg3,sp  // &elf_tmp
    call upx_so_main  // (&so_info, &argc); returns &escape_hatch
    add sp,sp,#MAX_ELF_HDR_32
    mov lr,r0  // save &escape_hatch
    ldmia sp!,{r0,r1,r2}  // F_ADRU, F_LENU, PMASK  (unfolded region)
    mov r7,#0xff & __NR_munmap  // FIXME depends on HW and ABI of OS
    mov pc,lr  // goto &escape_hatch

L10:
  section ptr_NEXT
    mov r0,pc
    ret
// De-compressor sections inserted here:
// section EXP_HEAD
// section NRV_HEAD
// section NRV2B
// section NRV2D
// section NRV2E
// section NRV_TAIL
// section LZMA_*
// section ZSTD  future
// section EXP_TAIL

  section SO_TAIL
#if defined(ARMEL_DARWIN)  /*{*/
        mov r7,#0
        mov r12,#0xff & __NR_munmap
#elif defined(ARMEL_EABI4)  /*}{*/
        mov r12,#0
        mov r7, #0xff & __NR_munmap
#elif defined(ARM_OLDABI)  /*{*/
        mov r7,#0
        mov r12,#0
#endif  /*}*/
        ldr pc,[r2,#4 -2*4]  @ Elf32_auxv_t[AT_NULL@.a_type].a_val

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
        strb r1,[r0],#1; subs r2,r2,#1
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
__NR_munmap=   91 + __NR_SYSCALL_BASE  // 0x5b
__NR_mprotect=125 + __NR_SYSCALL_BASE
__NR_msync=   144 + __NR_SYSCALL_BASE  // 0x90
__NR_open=      5 + __NR_SYSCALL_BASE
__NR_read=      3 + __NR_SYSCALL_BASE
__NR_stat=    106 + __NR_SYSCALL_BASE
__NR_uname=   122 + __NR_SYSCALL_BASE
__NR_unlink=   10 + __NR_SYSCALL_BASE
__NR_write=     4 + __NR_SYSCALL_BASE

.globl Pwrite; Pwrite: b write

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
.globl mprotect;  mprotect:  do_sys __NR_mprotect; ret
.globl msync;     msync:     do_sys __NR_msync; ret
.globl munmap;    munmap:    do_sys __NR_munmap; ret
.globl open;      open:      do_sys __NR_open; ret
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
        mov r12,#~0; mov r12,r12,lsl #12  // PAGE_MASK
        bic r12,arg1,r12  // lo frag
        sub arg1,arg1,r12  // page align lo end
        add arg2,arg2,r12
        do_sys __NR_mmap2
        ldmia sp!,{r4,r5,pc}

O_RDWR= 2
O_DIRECTORY= 040000
O_TMPFILE= 020000000
        .balign 4
table3:
        .word O_RDWR | O_DIRECTORY | O_TMPFILE
        .word 0700
        .asciz "/dev/shm"; .balign 4

upxfd_create: .globl upxfd_create
    bkpt  // upxfd_create
        adr r0,table3
        ldmia r0!,{r1,r2}
        do_sys7t2 __NR_open
        ret

        .globl __clear_cache
__clear_cache:
        bkpt  // clear_cache  should not be needed: write() + mmap()

get_sys_munmap: .globl get_sys_munmap  // r0= system call instruction
#if defined(ARMEL_DARWIN)  /*{*/
        ldr r0,4*1 + munmap
#elif defined(ARMEL_EABI4)  /*}{*/
        ldr r0,4*2 + munmap
#elif defined(ARM_OLDABI)  /*}{*/
        ldr r0,4*0 + munmap
#else  /*}{*/
        mov r0,#0
#endif  /*}*/
        ret

mmap_privanon: .globl mmap_privanon
        stmdb sp!,{r4,r5,lr}
        mov r4,#MAP_PRIVATE|MAP_ANONYMOUS  @ Linux: MAP_PRIVATE|MAP_ANON; QNX:MAP_PRIVANON
        mov r5,#0  @ offset= 0
        orr r3,r3,r4  @ combine with input (such as MAP_FIXED)
        mvn r4,#0  @ fd= -1
        b mmap_do


underlay: .globl underlay  // (unsigned size, char *ptr, unsigned page_mask);
    stmdb sp!,{r0,r1,r2,r3,r4,r5,r6,r7, lr}
    ldmia sp!, {r4,r5,r6,r7}  // r4= r0; r5= r1; r6= r2; r7= r3;
size .req r4
ptr  .req r5
pmsk .req r6
frag .req r7
tmp  .req r3
    mov r0,sp  // old sp
    bics frag,ptr,pmsk; beq 3f  // page fragment
    sub tmp,sp,frag
    and sp,tmp,#-2*NBPW
    str r0,[sp,#-NBPW]!  // save old sp for pop at return

    mov r2,frag
    and r1,ptr,pmsk  // beginning of page
    add r0,sp,#NBPW  // &saved_area
    bl memcpy
3:

    and r0,ptr,pmsk  // beginning of page
    add r1,size,frag  // include fragment
    mov r2,#PROT_WRITE|PROT_READ
    mov r3,#MAP_FIXED
    bl mmap_privanon  // r0= ptr because MAP_FIXED
    mov ptr,r0

    cmp frag,#0; beq 3f
    mov r0,ptr  // mapped address
    add r1,sp,#NBPW  // &saved_area
    mov r2,frag
    bl memcpy
    ldr sp,[sp]  // original sp
3:
    mov r0,ptr  // start of mapped region
    ldmia sp!,{r4,r5,r6,r7, pc}

    .unreq tmp

    .unreq size
    .unreq ptr
    .unreq pmsk
    .unreq frag

my_alloca: .globl my_alloca
        sub r0,sp,r0
        and r0,r0,#-2*NBPW
        mov sp,r0
        ret

#if 1|DEBUG  /*{*/

__udivsi3: .globl __udivsi3
div10: .globl div10
        mov ip,r0  @ extra copy used at end
        sub r1,r1,r1  @ hi

        mov r2,r0  @ copy lo
        adds r0,r0,r0,lsl #3   @ 9*lo
        adc  r1,r1,r1,lsl #3   @ 9*hi + C
        add  r1,r1,r2,lsr #(32 - 3)  @ bits shifted from lo to hi

        mov r2,r0  @ copy lo
        adds r0,r0,r0,lsl #4
        adc  r1,r1,r1,lsl #4
        add  r1,r1,r2,lsr #(32 - 4)  @ * 0x99

        mov r2,r0  @ copy lo
        adds r0,r0,r0,lsl #8
        adc  r1,r1,r1,lsl #8
        add  r1,r1,r2,lsr #(32 - 8)  @ * 0x9999

        mov r2,r0  @ copy lo
        adds r0,r0,r0,lsl #16
        adc  r1,r1,r1,lsl #16
        add  r1,r1,r2,lsr #(32 - 16)  @ * 0x99999999

        subs r0,r0,ip,lsl #(32 - 1)  @ - * 0x80000000
        sbc  r1,r1,ip,lsr #1         @   * 0x19999999

        adds r0,r0,ip
        adc  r0,r1,#0  @ * 0x0.1999999a
        ret

#endif  /*}*/

/* vim:set ts=8 sw=8 et: */
