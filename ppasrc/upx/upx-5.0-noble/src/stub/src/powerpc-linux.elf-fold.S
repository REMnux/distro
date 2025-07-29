/*  powerpc-linux.elf-fold.S -- linkage to C code to process ELF binary
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) 1996-2025 Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) 1996-2025 Laszlo Molnar
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

NBPW= 4  // Number of Bytes Per Word
AL_STK= 0x10  // stack alignment
#include "arch/powerpc/32/macros.S"
#include "arch/powerpc/32/ppc_regs.h"

PATH_MAX= 4096  // /usr/include/linux/limits.h

AT_NULL= 0

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4

sz_l_info= 12
sz_p_info= 12

MAP_PRIVATE=   0x02
MAP_FIXED=     0x10

PROT_READ=     0x1

O_RDONLY=       0

OVERHEAD= 2048

// http://refspecs.linuxfoundation.org/elf/elfspec_ppc.pdf  p.3-17 (pdf p.33)
// SZ_LINKA= (2 + max(0, #params - 8))*NBPW  // (sp,lr, arg9,arg10, ... )
SZ_LINKA= (2 + 2)*NBPW  // (sp,pc, arg9,arg10,... ) and 16-byte aligned
SZ_FRAME= SZ_LINKA

// In:
r_exp=   31  // f_exp == &decompress
  r_buf= 30
r_ADRU=  29  // &base to unmap
r_LENU=  28  // length to unmap
r_fd=    27  // open fd of /proc/self/exe
r_auxv=  26
r_elfa=  25  // original &Elf32_Ehdr of stub
r_ADRX=  24  // compressed input
r_LENX=  23  // total size
r_FLD=   22
// Local:
cblk=    21
  r_90b=   r_FLD
r_PMASK= 20  // (in) PAGE_MASK
av_hi=   19
av_len=  18

page_mask:
        .int -0x1000  // default page mask (4KiB)
        .int 0  // something else?
        b fold_begin

        .balign 4
get_page_mask: .globl get_page_mask
        mflr r0  // retaddr
        call 0f; 0: mflr a0
        mtlr r0  // original retaddr
        lwz a0,page_mask - 0b(a0)
        blr

Pprotect: .globl Pprotect
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b mprotect

Psync: .globl Psync  // (addr, len, flags)
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0

// System calls write() and msync(,,MS_SYNC) should implicitly flush dcache
// over the covered region before doing the write().
// But strange errors were observed, so flush explicitly.
CACHELINE=32
sweep= a3  // temp addr
dlast= a4  // final addr
        add dlast,a0,a1  // addr + len
        addi dlast,dlast,-1  // highest covered addr
        ori sweep,a0,-1+ CACHELINE  // highest addr on initial cache line
fl_loop:
        dcbst  0,sweep  // initiate store (modified) cacheline to memory
        cmpl cr0,sweep,dlast  // did we cover the highest-addressed byte?
        icbi   0,sweep  // discard instructions from cacheline
        addi     sweep,sweep,CACHELINE  // highest addr on next line
        blt  cr0,fl_loop  // not done yet

        sync   // wait for all memory operations to finish
        isync  // discard prefetched instructions (if any)

        b msync

Pmap: .globl Pmap
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b mmap

Punmap: .globl Punmap
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b munmap

fold_begin:
        mtctr r0  // # words before argc  FIXME: fragile
        lwz r0,0(r_FLD)  // O_BINFO | is_ptinterp | unmap_all_pages
        slwi r0,r0,3*4
        mtcrf 0x8,r0  // cr4.eq = unmap_all_pages
        call L90
L90b:
        .asciz "   =/proc/self/exe"
L_PFX= 4  // strlen("   =")
        .balign 4
L90:
        mflr r_90b
// slide {<<stuff>>,argc,argv,0,env,0,auxv} down with maximum room before strings
        la a1,-NBPW(sp)  // src ready for lwzu
    beq cr4,0f; la sp,-(-AL_STK & (-1+ AL_STK + (NBPW + L_PFX + PATH_MAX)))(sp); 0:
        la a0,-NBPW(sp)  // dst ready for stwu
0: // copy stuff below argc (count in r0 at fold_begin)
        lwzu r0,NBPW(a1)
        stwu r0,NBPW(a0); bdnz 0b

        lwzu r0,NBPW(a1)  // argc (could be zero!)
        stwu r0,NBPW(a0)
0: // copy argv
        lwzu r0,NBPW(a1); cmplwi cr0,r0,0
        stwu r0,NBPW(a0); bne cr0,0b
0: // copy env
        lwzu r0,NBPW(a1); cmplwi cr0,r0,0
        stwu r0,NBPW(a0); bne cr0,0b

        la r_auxv,NBPW(a0)
0: // copy auxv
        lwz  r0,NBPW(a1); cmplwi cr0,r0,AT_NULL
        stw  r0,NBPW(a0)
        lwzu r0,2*NBPW(a1)
        stwu r0,2*NBPW(a0); bne cr0,0b

        La av_hi,NBPW(a0)  // tmp end of auxv

    beq cr4,no_pse_env
        subf av_len,r_auxv,av_hi  // length of auxv
        lwz  r0,0(r_90b)  // "    ="
        la cblk,NBPW(a1)  // original &strings
        stwu r0,NBPW(a0)
        la  r_buf,L_PFX(a0)  // buffer
// r_fd = open("/proc/self/exe", O_RDONLY)
        li a1,O_RDONLY
        la a0,L_PFX(r_90b)  //     "/proc/self/exe"
        call open; mr r_fd,a0
// readlink("/proc/self/exe", buffer, -1+ PATH_MAX)
        li a2,-1+ PATH_MAX
        movr a1,r_buf  // buffer
        la a0,L_PFX(r_90b)  //     "/proc/self/exe"
        call readlink; la a2,-L_PFX(r_buf)  // a0= len; a2= buffer
        cmpwi a0,0; bgt 0f  // success
        la a2,0(r_90b)  // "   =/proc/self/exe"
        li a0,L90  - (NBPW+ L90b)  // round_up(NBPW, strlen("/proc/self/exe"))
0:
        addi a0,a0,L_PFX
        add a1,a2,a0  // beyond end of path and prefix
        mtctr a0  // strlen(env_var)
        mr a0,cblk  // old &strings
        li r0,0; stbu r0,-1(a0)  // NUL terminator
0: // slide path up
        lbzu r0,-1(a1)
        stbu r0,-1(a0); bdnz 0b
        mr cblk,a0  // new env_ptr
        clrrwi a0,a0,4  // .balign AL_STK
        la a1,NBPW(av_hi)
        sub r0,a1,sp; neg r0,r0; clrlwi r0,r0,32-4
        sub a0,a0,r0

        mr a1,av_hi
        srwi r0,av_len,2; mtctr r0
0: // slide auxv up
        lwzu r0,-NBPW(a1)
        stwu r0,-NBPW(a0); bdnz 0b
        mr r_auxv,a0
// Add env_ptr
        lwzu r0,-NBPW(a1)
        stwu r0,-NBPW(a0)  // env terminator
        stwu cblk,-NBPW(a0)  // added env_ptr

        sub r0,a1,sp
        srwi r0,r0,2; mtctr r0
// slide env, argv, rest up
0:
        lwzu r0,-NBPW(a1)
        stwu r0,-NBPW(a0); bdnz 0b

        mr sp,a0

no_pse_env:
        stwu sp,-(SZ_FRAME+OVERHEAD)(sp)  // allocate this frame
        mr a0,r_ADRX  // &b_info
        mr a1,r_LENX  // total_size
        mr a2,r_elfa  // elfaddr
        mr a3,r_auxv  // &Elf32_auxv_t
        la a4,SZ_FRAME(sp)  // &Elf32_Ehdr temporary space
        call upx_main  // Out: a0= entry
// entry= upx_main(b_info *a0, total_size a1, Elf32_Ehdr *a2, ELf32_auxv_t *a3,
//      tmp_ehdr[])

        la  sp,SZ_FRAME+OVERHEAD(sp)  // deallocate this frame
        mr r_exp,a0  // save &entry

sz_Ehdr= 13*NBPW
e_type= 16
ET_EXEC= 2
sz_Phdr= 8*NBPW
p_vaddr= 2*NBPW
p_memsz= 5*NBPW
// Discard pages of compressed data (includes [ADRX,+LENX) )
        lwz a1,p_memsz+sz_Phdr+sz_Ehdr(r_elfa)  // Phdr[C_TEXT= 1].p_memsz
        //lhz r0,e_type(r_elfa); cmpwi r0,ET_EXEC; bne 1f  // only ET_EXEC
        movr a0,r_elfa; call brk  // also set the brk
1:
        lwz a1,p_memsz+sz_Phdr+sz_Ehdr(r_elfa)  // Phdr[C_TEXT= 1].p_memsz
        movr a0,r_elfa; call munmap  # discard C_TEXT compressed data

    beq cr4,no_map_pse
// first page of /proc/self/exe, to preserve it despite munmap(ADRU, LENU)
        li a5,0  // offset
        movr a4,r_fd
        cmpwi a4,0; blt no_map_pse
        li a3,MAP_PRIVATE
        li a2,PROT_READ
        neg a1,r_PMASK  // page_size
        li a0,0  // kernel chooses where
        call mmap
// close /proc/self/exe
        movr a0,r_fd
        call close
no_map_pse:

AT_NULL= 0  // <elf.h>
a_type= 0
a_val= NBPW
sz_auxv= 2*NBPW

// find the escape hatch in auxv[{AT_NULL}].a_val
        mr a0,r_auxv
0:
        lwz r0,a_type(a0); lwz a1,a_val(a0); addi a0,a0,sz_auxv
        cmplwi cr0,r0,AT_NULL; bne+ cr0,0b
        mtctr a1  // escape hatch

        mr a0,r_ADRU
        mr a1,r_LENU
        li r0,SYS_munmap
        mtlr r_exp  // entry address

        lmw a2,SZ_FRAME+(a2 - r2 + 2)*NBPW - NBPW(sp) // restore registers a2 thru r31
        la sp, SZ_FRAME+32*NBPW(sp)  // deallocate outer frame

        bctr  // goto escape hatch

  section SYSCALLS

SYS_exit=  1
SYS_fork=  2
SYS_read=  3
SYS_write= 4
SYS_open=  5
SYS_close= 6

SYS_brk=       45
SYS_readlink=  85
SYS_mmap=      90
SYS_munmap=    91
SYS_ftruncate= 93
SYS_mprotect= 125
SYS_msync=    144
SYS_openat=   286
SYS_memfd_create= 360

exit: .globl exit
        li r0,SYS_exit;     5: b 5f
brk: .globl brk
        li r0,SYS_brk;      5: b 5f
readlink: .globl readlink
        li r0,SYS_readlink; 5: b 5f
ftruncate: .globl ftruncate
        li r0,SYS_ftruncate;5: b 5f
close: .globl close
        li r0,SYS_close;    5: b 5f
write: .globl write
        li r0,SYS_write;    5: b 5f
read: .globl read
        li r0,SYS_read;     5: b 5f
open: .globl open
        li r0,SYS_open;     5: b 5f
openat: .globl openat
        li r0,SYS_openat;   5: b 5f
mprotect: .globl mprotect
        li 0,SYS_mprotect;  5: b 5f
msync: .globl msync
        li 0,SYS_msync;     5: b 5f
munmap: .globl munmap
        li r0,SYS_munmap;   5: b sysgo
mmap: .globl mmap
        li r0,SYS_mmap
sysgo:
#ifndef TRACE  //{
#define TRACE 0
#endif  //}

#if TRACE  //{
FD_STDERR= 2
Tr1= 0*NBPW
Tr0= 1*NBPW
Tr3= 2*NBPW  // a0
Tr4= 3*NBPW  // a1
Tr5= 4*NBPW  // a2
Tr6= 5*NBPW  // a3
Tr7= 6*NBPW  // a4
Tr8= 7*NBPW  // a5
Tlr= 8*NBPW
Tctr= 9*NBPW
Tbuf= 10*NBPW
T_FRAME= 10*NBPW + 96
        stwu sp,-T_FRAME(sp)
        stw r0,Tr0(sp)  // SYS_n
        stw r3,Tr3(sp)  // a0
        stw r4,Tr4(sp)  // a1
        stw r5,Tr5(sp)  // a2
        stw r6,Tr6(sp)  // a3
        stw r7,Tr7(sp)  // a4
        stw r8,Tr8(sp)  // a5
        mflr  r0; stw r0,Tlr(sp)
        mfctr r0; stw r0,Tctr(sp)
outp=   r3
p_word= r4
Tw=     r5
Thex=   r6
nib=    r7

        call get_Thex
        la outp,-1+Tbuf(sp)  // output ptr (for update)
        la p_word,-NBPW+Tr1(sp)
Lword:
        lwzu Tw,NBPW(p_word)  // next word
        call Tword
        la r0,NBPW+Tr8(sp)
        cmpw r0,p_word; bgt Lword
        li r0,' '; call Tflush

        lwz r0,Tlr(sp); mtlr r0
        lwz r0,Tctr(sp); mtctr r0
        lwz r0,Tr0(sp)
        lwz a0,Tr3(sp)
        lwz a1,Tr4(sp)
        lwz a2,Tr5(sp)
        lwz a3,Tr6(sp)
        lwz a4,Tr7(sp)
        lwz a5,Tr8(sp)
#endif  //}
        sc
        bns+ no_fail  // 'bns': branch if No Summary[Overflow]
        neg a0,a0  // failure: return -errno (always >[unsigned] PAGE_MASK)
no_fail:
#if TRACE //{
        stw r0,Tr0(sp)  // SYS_n
        stw r3,Tr3(sp)  // a0
        stw r4,Tr4(sp)  // a1
        stw r5,Tr5(sp)  // a2
        stw r6,Tr6(sp)  // a3
        stw r7,Tr7(sp)  // a4
        stw r8,Tr8(sp)  // a5
        mflr  r0; stw r0,Tlr(sp)
        mfctr r0; stw r0,Tctr(sp)

        mr Tw,a0  // value from sc
        call get_Thex
        la outp,-1+Tbuf(sp)  // output ptr (for update)
        la p_word,NBPW+Tr8(sp); call Tword  // one word only
        li r0,'\n'; call Tflush

        lwz r0, Tlr(sp); mtlr  r0
        lwz r0,Tctr(sp); mtctr r0
        lwz r0,Tr0(sp)
        lwz a0,Tr3(sp)
        lwz a1,Tr4(sp)
        lwz a2,Tr5(sp)
        lwz a3,Tr6(sp)
        lwz a4,Tr7(sp)
        lwz a5,Tr8(sp)
        addi sp,sp,T_FRAME
#endif  //}
        ret
#if TRACE  //{
Tword:
        li r0,8; mtctr r0  // 8 nibbles per word
        li r0,' '; stbu r0,1(outp)  // leading punctuation for word
Tnib:
        rotlwi Tw,Tw,4; andi. nib,Tw,0xF; add nib,nib,Thex
        lbz  r0,0(nib)
        stbu r0,1(outp)
        bdnz Tnib
        ret

Tflush:
        stbu r0,1(outp)  // terminating punctuation
        la outp,1(outp)  // update adjust
        la a1,Tbuf(sp)  // in Tflush
        subf a2,a1,outp
        li a0,FD_STDERR; li r0,SYS_write; sc  // write(FD_STDERR, ptr, size)
        ret

get_Thex:
        mflr r0
        call 0f; .asciI "0123456789abcdef"; 0:
        mflr Thex
        mtlr r0; ret
#endif  //}

__NR_memfd_create= 360
MFD_EXEC= 0x10
EINVAL= 22

memfd_create: .globl memfd_create
        mflr r0; stwu r0,-2*NBPW(sp)
        li a1,MFD_EXEC  // modern clue
mfd_try:
        call 0f; .asciz "upx"; 0:
        mflr a0
SYS_memfd_create= __NR_memfd_create
        li r0,SYS_memfd_create; call sysgo
        cmpi cr7,a0,0; bge cr7,0f  // success
        cmpi cr6,a1,0; bne cr6,1f  // not 2nd time
8:
        teq r3,r3  // 2nd error, or unexpected 1st error
1:
        cmpi cr7,a0,-EINVAL; bne cr7,8b  // unexpected 1st error
        li a1,0; b mfd_try  // 2nd attempt
0:
        lwz r0,0(sp); la sp,2*NBPW(sp)
        mtlr r0; ret

memcpy: .globl memcpy  // (dst, src, n)
        cmpwi a2,0; beq- 9f
        mtctr a2
        subi a3,a0,1
        subi a1,a1,1
0:
        lbzu r0,1(a1)
        stbu r0,1(a3)
        bdnz 0b
9:
        blr  // return original dst

memset: .globl memset  // (dst, val, n)
        cmpwi a2,0; beq- 9f
        mtctr a2
        subi a3,a0,1
0:
        stbu a1,1(a3)
        bdnz 0b
9:
        blr  // return original dst

my_bkpt: .globl my_bkpt
        teq r0,r0  // my_bkpt
        blr
/* vim:set ts=8 sw=8 et: */
