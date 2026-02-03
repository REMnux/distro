/*  riscv64-linux.elf-entry.S -- Linux program entry point & decompressor (Elf binary)
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) Laszlo Molnar
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

#include "arch/riscv/64/macros.S"
#include "arch/riscv/64/regs.h"

#define bits x11 /* x22  a1  arg2 */
#define ta x12   /* x12  a2  arg3 */
#define tb x13   /* x13  a3  arg4 */

NBPW= 8

/* These from /usr/include/unistd_64.h */
__NR_close=     57
__NR_exit=      93
__NR_memfd_create= 279
__NR_mmap=     222
__NR_openat=    56
__NR_write=     64

sz_Ehdr= 64
e_phnum= 56
sz_Phdr= 56

sz_l_info= 12
  l_lsize= 8

sz_p_info= 12

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8

AT_PAGESZ= 6

PROT_READ=  1
PROT_WRITE= 2
PROT_EXEC=  4

FD_CWD= -100

MAP_SHARED=  1
MAP_PRIVATE= 2
MAP_FIXED=     0x10
MAP_ANONYMOUS= 0x20

MFD_EXEC= 0x0010

SYS_mmap= 9  // 64-bit mode only!

FD_stderr= 2

M_NRV2B_LE32=2  // ../conf.h
M_NRV2D_LE32=5
M_NRV2E_LE32=8

// same as in riscv64-linux.elf-fold.S
F_FRAME= 8*NBPW
F_EOFDST=7*NBPW
F_EOFSRC=6*NBPW; F_ENTR= F_EOFSRC
F_RDX=  5*NBPW
F_LENU= 4*NBPW  // length of Uncompressed stub
F_ADRU= 3*NBPW; F_PMASK= F_ADRU
F_ELFA= 2*NBPW
 F_MFD= 1*NBPW + 4  // 32-bit file descriptor
F_LENC= 1*NBPW  // 32-bit length of Compressed stub
F_ADRC= 0*NBPW

D_FOLD=  2*NBPW  // .data space at start of unfold
D_PMASK= 0*NBPW
D_XSIGSEGV= 1*NBPW

// https://www.uclibc.org/docs/psABI-x86_64.pdf
  section ELFMAINX
#define elfa s3
sz_pack2= .-4
_start: .globl _start
        jal ta,0f; 0: addi ta,ta,-8  // &sz_pack2

//// ebreak# uncomment for debugging
        lwu tb,0(ta)  // sz_pack2
        sub elfa,ta,tb

        ld s0,0(sp)  // argc
        addi s1,sp,NBPW  // &argv

        addi sp,sp,-F_FRAME
        sd elfa,F_ELFA(sp)

        //NYI lea cancel_dummy(%rip),%r15

  section ELFMAINX2

// find auxv
        slli ta,s0,3  // NBPW * argc
        add ta,ta,s1  // end argv
0: // find end of env
        addi ta,ta,NBPW  // &env[k]
        ld tb,(ta); bnez tb,0b

// find AT_PAGESZ in auxv
        addi ta,ta,NBPW  // &auxv
        li rv,AT_PAGESZ  // desired key
0:
        ld tb,(ta); ld bits,NBPW(ta); addi ta,ta,2*NBPW
        beq tb,rv,9f  // found it
        bnez tb,0b  // keep searching
        li bits,0x1000  // default PAGE_SIZE
9:
        neg rv,bits  // PAGE_MASK
        sd rv,F_PMASK(sp)
// Create anonymous temporary file on mfd; like upxfd_create
        jal arg1,0f
        .asciz "upx"  // 4==size; no .balign needed
0:
        li arg2,MFD_EXEC  // flags
        syscall __NR_memfd_create
        bgez a0,9f  // success
            // failure, so try /dev/mem
O_RDWR= 2
O_DIRECTORY= 0200000  // 0x010000
O_TMPFILE= 020000000  // 0x400000
        li arg4,0700  // mode
        li arg3,O_RDWR | O_TMPFILE | O_DIRECTORY
        jal arg2,0f
        .ascii "/dev/mem"; .int 0  // .balign causes problems
0:
        li arg1,FD_CWD
        syscall __NR_openat
9:
        sw rv,F_MFD(sp)

#define binf s1
        jal mainz
        sub rv,binf,elfa
        sw rv,F_LENC(sp)

        lwu rv,0(binf)
        add rv,rv,elfa
        sd rv,F_ADRC(sp)

        lw rv,4+sz_unc(binf)
        sw rv,F_LENU(sp)

#define old_sp s9
        mv old_sp,sp
// alloca(lenu)
        sub rv,sp,rv; andi sp,rv,-2*NBPW

// Decompress the rest of this loader, and jump to it.

#include "riscv64-getbit.h"
        mv dst,sp
        lbu ta,4+b_method(binf)
        li  tb,M_NRV2B_LE32|(0<<8)
        beq ta,tb,0f; ebreak; 0:  # elf_entry wrong method
        addi src,binf,4 + sz_b_info
        lwu rv,4+sz_unc(binf)
        add rv,rv,dst
        sd rv,F_EOFDST(old_sp)
        lwu rv,4+sz_cpr(binf)
        add rv,rv,src
        sd  rv,F_EOFSRC(old_sp)
                // value in register binf is dead

//s9  === old_sp:  array of F_FRAME

        jal x5,xin_n2b

#include "riscv64-getbit.S"
#define NO_METHOD_CHECK 1
xin_n2b:
#include "arch/riscv/64/nrv2b_d.S"

n2b_EOFbad:
        ebreak  # elf-entry n2b_EOFbad
eof_n2b:
        ld  ta,F_EOFSRC(old_sp)
        bne ta,src,n2b_EOFbad
        ld  ta,F_EOFDST(old_sp)
        bne ta,dst,n2b_EOFbad

// propagate F_PMASK(old_sp) into c.lui at D_PMASK(sp)
        lhu ta,F_PMASK(old_sp)
        lhu tb,D_PMASK(sp)  # old c.lui
        srli ta,ta,12-2  # position PMASK to nzimm[16:12]
        xor tb,tb,ta  # bits which differ
        andi ta,ta,037<<2  # restrict to nzimm[16:12]
        xor ta,ta,tb  # change them
        sh ta,D_PMASK(sp)  # new c.lui

// Write de-compressed 'fold' to file
        lwu arg3,F_LENU(old_sp)
        mv arg2,sp
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
        li arg3,PROT_EXEC|PROT_READ  // FIXME: add PROT_WRITE for DEBUG only
        lwu arg2,F_LENU(sp)
        li arg1,0  // (%arg1)dst = 0;  // kernel chooses addr
        syscall __NR_mmap; bgez rv,0f; ebreak; 0:
        sd rv,F_ADRU(sp)

        lwu arg1,F_MFD(sp)
        syscall __NR_close

// Use the copy.
        ld a0,F_ADRU(sp)  //
        addi a0,a0,D_FOLD  // beyond .data
        jr a0  // goto unfolded stub

        // IDENTSTR goes here

  section ELFMAINZ
        .balign 4
mainz:
        jalr binf,ra
        .long O_BINFO  // offset of b_info for .text | is_ptinerp | unmap_all_pages
FOLD:
        // { b_info={sz_unc, sz_cpr, {4 char}}, folded_loader...}

/*__XTHEENDX__*/

/* vim:set ts=8 sw=8 et: */
