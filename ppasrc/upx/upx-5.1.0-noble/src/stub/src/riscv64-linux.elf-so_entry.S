/*  riscv64-linux.elf-so_entry.S -- Linux DT_INIT & decompressor (Elf shared lib)
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) 1996-2021 Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) 1996-2021 Laszlo Molnar
*  Copyright (C) John F. Reiser
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

NBPW= 8
#include "arch/riscv/64/macros.S"
#include "arch/riscv/64/regs.h"

#define DEBUG 1

sz_Elf64_Ehdr = 8*NBPW
sz_Elf64_Phdr = 7*NBPW

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

MFD_EXEC= 0x0010

FD_stderr= 2

M_NRV2B_LE32=2  // ../conf.h
M_NRV2D_LE32=5
M_NRV2E_LE32=8

// /usr/include/asm-generic/unistd.h
__NR_close    = 0x39  //  57
__NR_exit     = 0x5d  //  93
__NR_memfd_create = 0x117  // 279
__NR_mmap     = 0xde  // 222
__NR_mprotect = 0xe2  // 226
__NR_munmap   = 0xd7  // 215
__NR_openat   = 0x38  //  56
__NR_read     = 0x3f  //  63
__NR_write    = 0x40  //  64

#define old_sp x25  /* BUG: callee did not save */

  section ELFMAINX
//  .long offset(b_info)|(asl_delta>>12)  src for f_exp  FIXME: really?
//SO_INFO:
//  .word offset(.)  // detect relocation
//  .word offset(user DT_INIT)
//  .word offset(escape_hatch)  // override with round_up(2, PT_LOAD[0]{.p_memsz + .p_vaddr})
//  .word offset(dst for f_exp)

        .balign 4
_start: .globl _start
        jal x5,fold_info  // x5= 4+ _start; sets binf= &b_info
#define binf arg6
        PUSH4 a0,a1,a2,ra  // MATCH_00  argc,argv,envp,ra
        PUSH2 s0,s1  // MATCH_03  s0, s1 [ABI]
// sp displacements
F_FRAME= 8 * NBPW  // total size
F_EOFSRC=0 * NBPW
F_EOFDST=1 * NBPW
F_MFD=   2 * NBPW
F_PMASK= 3 * NBPW
F_S9=    4 * NBPW
F_ST4RT= 5 * NBPW
F_ADRU=  6 * NBPW
F_LENU=  7 * NBPW

F_ARGC=  F_FRAME + 2 * NBPW  // PUSH4 above
        addi sp,sp,-F_FRAME
        sd s9,F_S9(sp)
        sd x5,F_ST4RT(sp)

        lwu rv,sz_unc(binf)
        sd  rv,F_LENU(sp)
        mv old_sp,sp
// alloca(LENU)
        sub rv,sp,rv; andi sp,rv,-2*NBPW  // align alloca on stack

#define psa_fd   arg5
#define aux_end  arg5

AT_PAGESZ= 6
O_RDONLY= 0
        li  arg3,O_RDONLY
        jal arg2,0f; .asciz "/proc/self/auxv"; .balign 2; 0:
        li arg1,0  // FD_ ?
        syscall __NR_openat; mv psa_fd,rv

#define LEN_AUXV 1024
        addi sp,sp,-LEN_AUXV
      //mv arg1,rv  // fd
        mv arg2,sp  // buffer
        li arg3,LEN_AUXV  // len for 64 AT_* entries
        syscall __NR_read; mv arg1,psa_fd  // arg1 for close()
#undef psa_fd
        add aux_end,sp,rv  // sentinel
        syscall __NR_close
0:
        ld rv,NBPW(arg2)  // value
        ld arg3,0(arg2); addi arg2,arg2,2*NBPW  // tag
        addi arg3,arg3,-AT_PAGESZ; beqz arg3,1f
        bne arg2,aux_end,0b
#undef aux_end

        li rv,(1<<12)  // default 4KiB
1:
        neg rv,rv  // PAGE_MASK
        addi sp,sp,LEN_AUXV
        sd rv,F_PMASK(old_sp)  // PAGE_MASK

// Decompress the rest of this loader, and jump to it.

#include "riscv64-getbit.h"
#define tb x13  /* a3 arg4 */
        lbu ta,b_method(binf)
        li  tb,M_NRV2B_LE32|(0<<8)
        beq ta,tb,0f; bkpt; 0:  # so_elf:entry wrong method
        addi src,binf,sz_b_info
        lwu rv,sz_unc(binf)
        add rv,rv,sp  // sp is dst
        sd rv,F_EOFDST(old_sp)
        lwu rv,sz_cpr(binf)
                // value in register binf is dead
        add rv,rv,src
        sd  rv,F_EOFSRC(old_sp)
        mv dst,sp

        jal x5,xin_n2b
#include "riscv64-getbit.S"
xin_n2b:

// nrv2b code is hard-wired here
#define NO_METHOD_CHECK 1

// only one de-compressor; build 'eof' return
#undef DAISY_CHAIN

// use of mmap() forces implcit cache sync
#define NO_SYNC_CACHE 1

#include "arch/riscv/64/nrv2b_d.S"

n2b_EOFbad:
        bkpt  # elf-entry n2b_EOFbad
eof_n2b:
        ld  ta,F_EOFSRC(old_sp)
        bne ta,src,n2b_EOFbad
        ld  ta,F_EOFDST(old_sp)
        bne ta,dst,n2b_EOFbad

        li  arg2,MFD_EXEC
        jal arg1,0f; .asciz "upx"; .balign 2; 0:
        syscall __NR_memfd_create; sd rv,F_MFD(old_sp)

        ld arg4,F_PMASK(old_sp)
        sd arg4,0(sp)  // propagate PAGE_MASK

// Write de-compressed 'fold' to file
        lwu arg3,F_LENU(old_sp)
        mv  arg2,sp
        lwu arg1,F_MFD(old_sp)
L360:  // /dev/shm might be restricted to 8KiB at a time!
        syscall __NR_write
        add arg2,arg2,rv  // ptr += count
        sub  arg3,arg3,rv  // decrement count
        bnez arg3,L360  // not finished
// de-alloca()
        mv sp,old_sp

// Map unfolded code the SELinux way
        li arg6,0  // offset
        lwu arg5,F_MFD(sp)
        li arg4,MAP_PRIVATE
        li arg3,PROT_WRITE|PROT_EXEC|PROT_READ  // FIXME: add PROT_WRITE for DEBUG only
        lwu arg2,F_LENU(sp)
        li arg1,0  // (%arg1)dst = 0;  // kernel chooses addr
        syscall __NR_mmap; bgez rv,0f; bkpt; 0:
        sd rv,F_ADRU(sp)
#define u_ptr arg5
        mv u_ptr,rv

        lwu arg1,F_MFD(sp); syscall __NR_close

        ld x5,F_ST4RT(sp)  // 4+ _start
        ld s9,F_S9(sp)  // restore callee-saved register
        addi arg1,x5,-5*4  // &SO_INFO
        add arg2,sp,F_ARGC  // &{argc, argv, envp}
        addi sp,sp,F_ADRU
        jr 2*NBPW(u_ptr)

//%esp:
//  MATCH_04  ptr unfolded_code
//  MATCH_10  len unfolded_code
//  MATCH_00  argc,argv,envp,ra(_start)

f_expand:
// IDENTSTR goes here

  section ELFMAINZ
        .balign 4
fold_info:
        jalr binf,x5  // binf= &b_info; goto x5
//  b_info (sz_unc, sz_cpr, method) of folded code (C-language, etc.)

/* vim:set ts=8 sw=8 et: */
