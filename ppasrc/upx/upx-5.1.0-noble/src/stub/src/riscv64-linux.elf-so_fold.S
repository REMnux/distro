//  riscv64-linux.elf-so_fold.S -- linkage to C code to process Elf shared library
//
//  This file is part of the UPX executable compressor.
//
//  Copyright (C) John F. Reiser
//  All Rights Reserved.
//
//  UPX and the UCL library are free software; you can redistribute them
//  and/or modify them under the terms of the GNU General Public License as
//  published by the Free Software Foundation; either version 2 of
//  the License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; see the file COPYING.
//  If not, write to the Free Software Foundation, Inc.,
//  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
//  Markus F.X.J. Oberhumer              Laszlo Molnar
//  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
//
//  John F. Reiser
//  <jreiser@users.sourceforge.net>
//

#define DEBUG 1
#ifndef DEBUG  /*{*/
#define DEBUG 0
#endif  /*}*/

NBPW= 8
#include "arch/riscv/64/macros.S"
#include "arch/riscv/64/regs.h"
#define arg7 a6
#define call jal

#include "MAX_ELF_HDR.S"

MAP_ANONYMOUS= 0x20
MAP_PRIVATE=   0x02
MAP_FIXED=     0x10

__NR_close    = 0x39  //  57
__NR_exit     = 0x5d  //  93
__NR_memfd_create = 0x117  // 279
__NR_mmap     = 0xde  // 222
__NR_mprotect = 0xe2  // 226
__NR_msync    = 0xe3  // 227
__NR_munmap   = 0xd7  // 215
__NR_openat   = 0x38  //  56
__NR_read     = 0x3f  //  63
__NR_write    = 0x40  //  64

  section SO_HEAD
        .global PAGE_MASK  // workaround for bug in build chain
PAGE_MASK: .quad 0xfffffffffffff000  // default
upxfn_path:.quad 0  // displacement from "zero"

fold_begin: .globl fold
        j fold

get_page_mask: .globl get_page_mask
        auipc rv,0
        ld rv,-(2+ 2*8)(rv)
        ret

frag_align:  // CALLED VIA  "jal x5,frag_align" AT MOST 3 ARGUMENTS
        auipc arg4,0
        ld  arg4,-28(arg4)  # PAGE_MASK
        not arg4,arg4       # frag mask
        and arg4,arg1,arg4  # frag
        add arg2,arg2,arg4  # len += frag
        sub arg1,arg1,arg4  # pos -= frag  // aligned
        jr x5

Punmap: .globl Punmap
        jal x5,frag_align
munmap: .globl munmap
        syscall __NR_munmap; ret

// Sometimes Linux enforces page-aligned address
Pprotect: .globl Pprotect
mprotect: .globl mprotect
        jal x5,frag_align
        syscall __NR_mprotect; ret

mmap_privanon: .globl mmap_privanon
        li arg5,MAP_PRIVATE|MAP_ANONYMOUS
        or arg4,arg4,arg5  // combine with input (such as MAP_FIXED)
        li arg5,-1
        li arg6,0
        // FALL THROUGH to mmap

Pmap: .globl Pmap
        mv arg7,arg4
        jal x5,frag_align
        mv arg4,arg7
mmap: .globl mmap
        syscall __NR_mmap; ret

Psync: .globl Psync
        jal x5,frag_align
// fall into msync
        syscall __NR_msync; ret

fold:  // enter here (arg1= &so_info; arg2= &{argc,argv,envp,lr}
// sp/ ADRU, LENU, s0, s1, argc,argv,envp,ra
//  ADRU: MATCH_04  ptr unfolded_code
//  LENU: MATCH_10  len unfolded_code
//  s0,s1: ABI saved registers
//  MATCH_00  argc,argv,envp,ra
        addi sp,sp,-MAX_ELF_HDR_64; mv arg3,sp  // space for Elf64_Ehdr and Elf64_Phdrs
.globl upx_so_main
        call upx_so_main  // (&so_info, &argc, elf_tmp); returns &escape_hatch
        addi sp,sp, MAX_ELF_HDR_64
        mv   arg3,arg1  // save &escape_hatch
        POP4 arg1,arg2,s0,s1  // F_ADRU, F_LENU  (unfolded region); ABI
        li a7,__NR_munmap
        jr arg3  // syscall; POP4(x0,x1,x2,lr}; ret

get4:  .globl get4  // un-aligned fetch (little endian)
    mv  arg2,arg1
    lbu rv,  0(arg1)
    lbu arg3,1(arg2); slli arg3,arg3,1*8; or rv,rv,arg3
    lbu arg3,2(arg2); slli arg3,arg3,2*8; or rv,rv,arg3
    lbu arg3,3(arg2); slli arg3,arg3,3*8; or rv,rv,arg3
    ret

  section ptr_NEXT
        call 0f; 0:
        mv rv,ra

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

        .globl my_bkpt
my_bkpt:
        bkpt  // my_bkpt
        ret

// /usr/include/asm-generic/unistd.h
__NR_SYSCALL_BASE= 0

__NR_brk      = 0xd6 + __NR_SYSCALL_BASE  // 214
__NR_close    = 0x39 + __NR_SYSCALL_BASE  // 57
__NR_exit     = 0x5d + __NR_SYSCALL_BASE  // 93
__NR_ftruncate= 0x2e + __NR_SYSCALL_BASE  // 46
__NR_getpid   = 0xad + __NR_SYSCALL_BASE  // 172
__NR_mmap     = 0xde + __NR_SYSCALL_BASE  // 222
__NR_mprotect = 0xe2 + __NR_SYSCALL_BASE  // 226
__NR_msync    = 0xe3 + __NR_SYSCALL_BASE  // 227
__NR_munmap   = 0xd7 + __NR_SYSCALL_BASE  // 215
__NR_memfd_create = 0x117 + __NR_SYSCALL_BASE  // 279
__NR_openat   = 0x38 + __NR_SYSCALL_BASE  // 56
__NR_read     = 0x3f + __NR_SYSCALL_BASE  // 63
__NR_readlink = 0x4e + __NR_SYSCALL_BASE  // 78
__NR_unlinkat = 0x23 + __NR_SYSCALL_BASE  // 35
__NR_write    = 0x40 + __NR_SYSCALL_BASE  // 64

        .globl exit
exit:
        syscall __NR_exit

ftruncate:    .globl ftruncate;    syscall __NR_ftruncate;    ret
memfd_create: .globl memfd_create; syscall __NR_memfd_create; ret

        .globl read
read:
        syscall __NR_read; ret

Pwrite: .globl Pwrite
        .globl write
write:
        syscall __NR_write; ret

        .globl open
FD_CWD= -100
open:
        mv arg4,arg3
        mv arg3,arg2
        mv arg2,arg1
        li arg1,FD_CWD
          // fall into 'openat'
        .globl openat
openat:
        syscall __NR_openat; ret

        .globl close
close:
        syscall __NR_close; ret

        .globl unlinkat
unlinkat:
        syscall __NR_unlinkat; ret

        .globl getpid
getpid:
        syscall __NR_getpid; ret

        .globl brk
brk:
        syscall __NR_brk; ret

        .globl readlink
readlink:
        syscall __NR_readlink; ret

get_sys_munmap: .globl get_sys_munmap  // r0= system call instruction
        li rv,0x00000073  // ecall
        ret

my_memcpy: .globl my_memcpy  // impostor unknown to gcc
memcpy: .globl memcpy  // void *memcpy(void *dst, void const *src, size_t len)
        mv arg5,arg1; beqz arg3,9f  // rv
        add arg3,arg3,arg2  // src sentinel
0:
        lb arg4,0(arg2); addi arg2,arg2,1
        sb arg4,0(arg1); addi arg1,arg1,1; bne arg2,arg3,0b
9:
        mv rv,arg5
        ret

memset: .globl memset  // void *memset(void *dst, int c, size_t len);
        mv arg5,arg1; beqz arg3,9f  // rv
        add arg3,arg3,arg1  // dst sentinel
0:
        sb arg2,0(arg1); addi arg1,arg1,1; bne arg1,arg3,0b
9:
        mv rv,arg5
        ret

/* vim:set ts=8 sw=8 et: */
