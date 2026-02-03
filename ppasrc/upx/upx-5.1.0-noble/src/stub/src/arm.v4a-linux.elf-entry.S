/*  arm-linux.elf-entry.S -- Linux program entry point & decompressor (Elf binary)
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

NBPW= 4
#define ARMEL_EABI4 1
#include "arch/arm/v4a/macros.S"
#define call bl

arg1 .req r0
arg2 .req r1
arg3 .req r2
arg4 .req r3
arg5 .req r4
arg6 .req r5

sz_Elf32_Phdr =  8*NBPW
  p_vaddr = 2*NBPW
sz_Elf32_Ehdr = 13*NBPW
  e_type= 16
    ET_DYN= 3
  e_phnum= 16 + 2*2 + 5*NBPW + 2*2

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8
sz_l_info= 12
sz_p_info= 12

PROT_READ=  1
PROT_WRITE= 2
PROT_EXEC=  4

is_ptinterp=     (1<<0)
unmap_all_pages= (1<<1)

MAP_ANONYMOUS= 0x20
MAP_FIXED=     0x10
MAP_PRIVATE=   0x02

FD_CWD=        -1  // AT_CWD= -100
FD_stdin=       0
FD_stderr=      2
O_RDONLY=       0

AT_NULL=   0
AT_PAGESZ= 6

NAME_MAX=  255  // # chars in file name; linux/include/uapi/linux/limits.h

// Defaults unless overridden by AT_PAGESZ
PAGE_SHIFT= 12
PAGE_MASK=  (~0<<PAGE_SHIFT)
PAGE_SIZE = ( 1<<PAGE_SHIFT)

__NR_SYSCALL_BASE = 0

__NR_close=     6 + __NR_SYSCALL_BASE
__NR_execve=   11 + __NR_SYSCALL_BASE
__NR_exit=      1 + __NR_SYSCALL_BASE
__NR_fdatasync=148 + __NR_SYSCALL_BASE
__NR_fork=      2 + __NR_SYSCALL_BASE
__NR_fsync=   118 + __NR_SYSCALL_BASE
__NR_ftruncate=93 + __NR_SYSCALL_BASE
__NR_getpid=   20 + __NR_SYSCALL_BASE
__NR_getppid=  64 + __NR_SYSCALL_BASE
__NR_lseek=    19 + __NR_SYSCALL_BASE
__NR_memfd_create= 385 + __NR_SYSCALL_BASE
__NR_mkdir=    39 + __NR_SYSCALL_BASE
__NR_mmap2=   192 + __NR_SYSCALL_BASE
__NR_mprotect=125 + __NR_SYSCALL_BASE
__NR_msync=   144 + __NR_SYSCALL_BASE  // 0x90
__NR_open=      5 + __NR_SYSCALL_BASE
__NR_openat=  322 + __NR_SYSCALL_BASE
__NR_pipe=     42 + __NR_SYSCALL_BASE
__NR_read=      3 + __NR_SYSCALL_BASE
__NR_sigaction=67 + __NR_SYSCALL_BASE
__NR_stat=    106 + __NR_SYSCALL_BASE
__NR_uname=   122 + __NR_SYSCALL_BASE
__NR_unlink=   10 + __NR_SYSCALL_BASE
__NR_write=     4 + __NR_SYSCALL_BASE


__ARM_NR_BASE= 0xf0000 + __NR_SYSCALL_BASE
__ARM_NR_cacheflush=  2 + __ARM_NR_BASE

#ifndef DEBUG  /*{*/
#define DEBUG 0
#endif  /*}*/

#if DEBUG  //{
#define TRACE_REGS r0-r12,r14,r15
// sp (r13) is not included because the write-back might cause UNDEFINED behavior
// if the write-back register is not first or last.  The actual value of sp
// usually does not matter.  Just remember that lr (r14) and pc (r15) are stored
// one word closer to the stack pointer because r13 has been omitted.
#endif  //}

  section ELFMAINX
F_ADRX= 0*NBPW
  F_obinfo= F_ADRX  // unmap_all_pages in lo bits
F_LENX= 1*NBPW
F_ELFA= 2*NBPW
F_SEGV= 3*NBPW
F_ADRU= 4*NBPW
F_LENU= 5*NBPW
F_R0=   6*NBPW
F_R1=   7*NBPW
F_ENTR= 8*NBPW
  F_qflg= F_ENTR  // QNX mmap flags
F_SIZE= 9*NBPW

// (read-only) .data space at start of unfolded code
D_PMASK= 0*NBPW
D_QFLG=  1*NBPW
D_FNAME= 2*NBPW
D_XSEGV= 3*NBPW
D_FOLD=  4*NBPW  // start of code

r_pack2 .req r9
r_pmask .req r8

start_params:
sz_pack2= . - NBPW
mflg:
        .word MFLG  // MAP_{PRIVATE|ANONYMOUS}  // QNX vs linux
_start: .globl _start
////    nop; bkpt  // DEBUG
        ldr r_pack2,sz_pack2
        ldr r2,mflg
        adr r3,sz_pack2
        sub r3,r3,r_pack2  @ elfaddr= &Elf_Ehdr of this program
        call 0f; cancel_dummy: ret; 0:
        stmdb sp!,{r0,r1,r2}  // F_R0,F_R1,%F_ENTR(F_QFLG)
        sub sp,sp,#2*NBPW  // space for F_ADRU, F_LENU
        stmdb sp!,{r0,r1,r3,lr}  // %F_ADRX,%F_LENX,F_ELFA,F_SEGV

  section ELFSIGSEGV
// install SIGSEGV handler for debugging
SIGSEGV= 11
SA_SIGINFO= 4  // /usr/include/bits/sigaction.h
SA_RESTORER= 0x04000000
sa_sigaction = 0 * NBPW
sa_flags     = 1 * NBPW
sa_mask      = 3 * NBPW  // location of mask
sa_restorer  = 4 * NBPW
sa_frame = 5 * NBPW
        call adr_sigaction; mov r0,lr  // .sa_sigaction
        mov r1,#SA_SIGINFO  // .sa_flags
        mov r2,#0  // .sa_mask
        mov r3,#0
        mov r4,#0  // .sa_restorer
        stmdb sp!,{r0,r1,r2,r3,r4}

        mov arg4,#8  // 8 bytes  ==> 64 bits
        mov arg3,#0  // do not save old_sigaction
        mov arg2,sp  // &new_sigaction
        mov arg1,#SIGSEGV
        do_sys7t __NR_sigaction
        add sp,sp,#sa_frame

        call 0f
cancel_sigsegv:
        mov  r3,#8  // space for 8 bytes of signal flags
        mov r2,#0  // no old
        mov r1,#0  // no new
        mov r0,#SIGSEGV
        do_sys7t __NR_sigaction
        ret
0:
        str lr,[sp,#F_SEGV]

#if 0  //{ TEST ONLY
mov  r0,#0xc0;mov  r1,#0xc1;mov  r2,#0xc2;mov  r3,#0xc3;mov  r4,#0xc4;mov  r5,#0xc5;mov  r6,#0xc6;mov  r7,#0xc7
mov  r8,#0xc8;mov  r9,#0xc9;mov r10,#0xca;mov r11,#0xcb;mov r12,#0xcc
    ldr r0,[r0]  // cause SIGSEGV
#endif  //}

  section ELFMAINX2
        add arg1,sp,#NBPW + F_SIZE  // avoid feint of 0==argc
        call zfind  // out: r0= &envp
        call zfind

// set xPMASK by finding actual page size in Elf32_auxv
1:
        ldmia r0!,{r1,r2}
        cmp r1,#AT_PAGESZ; beq 2f
        cmp r1,#AT_NULL; bne 1b
        mov r2,#PAGE_SIZE  // default
2:
        mvn r2,r2; add r2,r2,#1  // neg
        mov r_pmask,r2


        call get_data  // cpr0 can be too far away
old_sp .req r11
binfo  .req r10
r_unc  .req r7
u_len  .req r6
        add binfo,lr,#NBPW  // skip o_binfo for now
unfold:
        ldr r_unc,[binfo,#sz_unc]
        mov r0,    #~0xff & (1+ NAME_MAX + 2*NBPW + D_FOLD + (1+ 11 + 13))
        add r0, r0,# 0xff & (1+ NAME_MAX + 2*NBPW + D_FOLD + (1+ 11 + 13))
        add u_len,r_unc,r0
        str u_len,[sp,#F_LENU]
// alloca for generated pathname (necessary if memfd_create fails)
        mov old_sp,sp
        sub sp,sp,r0
        and sp,sp,#-2*NBPW  // align stack

        mov r0,#0
        mov r1,sp
0:
        stmia r1!,{r0}
        cmp r1,old_sp; blo 0b

        mov arg3,sp  // &pathname (currently a null string "")
        mov arg2,u_len
        mov arg1,#0  // kernel chooses addr
        call upx_mmap_and_fd  // (addr + (1+ fd)) = (ptr, len, pathname)
        tst r0,#(1<<11); bpl 0f; bkpt; 0:  // fd "negative" ==> failure
        mov r1,r0,lsr #12
        mov r1,r1,lsl #12
        sub r0,r0,r1
        sub r0,r0,#1
//{ r0 and r1 are busy!

// copy generated pathname (if any) from stack into mapped region
        add r2,r1,r_unc
        add r2,r2,# 2*NBPW + D_FOLD
        and r2,r2,#-2*NBPW
0:
        ldmia sp!,{r3}  // gradual de-alloca
        stmia r2!,{r3}
        cmp sp,old_sp; blo 0b
mfd  .req old_sp
   .unreq old_sp
        str r1,[sp,#F_ADRU]
        mov mfd,r0
//}{ r0 free, r1 busy
        add r4,r_unc,# 2*NBPW + D_FOLD
        ldr r5,[sp,#F_SEGV]
        and r4,r4,   #-2*NBPW  // align displacement
        ldr r3,[sp,#F_qflg]
        mov r2,r_pmask
        stmia r1,{r2,r3,r4,r5}  // F_ADRU: D_PMASK, D_QFLG, D_FNAME, D_SEGV
  .unreq r_pmask

// De-compress folded stage of stub
        stmdb sp!,{r_unc}  @ P_01
        mov arg4,sp  @ &sz_unc = &dstlen
        add arg3,r1,#D_FOLD  @ dst
//} r1 free
        ldrb r0, [binfo,#b_method]
        stmdb sp!,{r0}  @ P_02  5th param to f_exp
        ldr arg2,[binfo,#sz_cpr]  @ srclen
        add arg1, binfo,#sz_b_info  @ src
#if DEBUG  /*{*/
        stmdb sp!,{TRACE_REGS}; mov r0,#2; bl trace
#endif  /*}*/
        call f_expand
        add sp,sp,#2*NBPW  @ P_02, P_01  remove 5th param


// faster than clearcache + msync; also avoids msync() bug
        ldr arg3,[sp,#F_LENU]
        ldr arg2,[sp,#F_ADRU]
        mov arg1,mfd
        do_sys7t __NR_write

        mov r5,#0
        mov r4,mfd
        mov r3,#MAP_PRIVATE|MAP_FIXED
        mov r2,#PROT_EXEC|PROT_READ
        ldr r1,[sp,#F_LENU]
        ldr r0,[sp,#F_ADRU]
        do_sys7t __NR_mmap2  // clobbers r7  r_unc

        mov r0,mfd
        do_sys7t __NR_close

// jmp unfolded_code
        ldr r0,[sp,#F_ELFA]
        ldr r1,[binfo,#-NBPW]  @ O_BINFO | unmap_all_pages
        add r4,r0,r1  @ ADRX= &b_info | unmap_all_pages
        bic r1,r1,#unmap_all_pages
        sub r5,r_pack2,r1  @ LENX= sz_pack2 - O_BINFO
        stmia sp,{r4,r5}  // sp: F_ADRX, F_LENX;  (sp no change)
#if DEBUG  /*{*/
        stmdb sp!,{TRACE_REGS}; mov r0,#3; bl trace
#endif  /*}*/
        ldr r12,[sp,#F_ADRU]
        add pc,r12,#D_FOLD  // goto unfolded code

proc_self_cmdline:
        .asciz "/proc/self/cmdline"
        .balign 4

#define r_fd r6
PATH_MAX= 4096
child:
#if 1  //{ pipe input to gdb
        mov arg1,#FD_stdin; do_sys7t __NR_close
        mov arg2,#0; mov arg1,#0; stmdb sp!,{arg1,arg2}  // space for result of pipe()
        mov arg1,sp
        do_sys7t __NR_pipe  // read side will be 0 (FD_stdin)
        ldmia sp!,{r0,r_fd}  // write side of pipe

        mov arg3,#commands_gdb_end - commands_gdb  // len
        adr arg2,commands_gdb
        mov arg1,r_fd
        do_sys7t __NR_write
        mov arg1,r_fd; do_sys7t __NR_close
#endif  //}

        sub sp,sp,#PATH_MAX
        mov arg3,#O_RDONLY
        adr arg2,proc_self_cmdline
        mov arg1,#FD_CWD
        do_sys7t2 __NR_openat; mov r_fd,r0  // fd
        mov arg2,sp  // buffer
        mov arg3,#PATH_MAX
        do_sys7t __NR_read
        mov arg1,r_fd; do_sys7t __NR_close

        do_sys7t __NR_getppid
        sub sp,sp,#16  // decimal(pid) fits in 16 bytes
        mov arg2,arg1; mov arg1,sp; call unsimal

        mov arg5,#0  // terminator
        mov arg4,sp  // &"pid"  (result of unsimal)
        add arg3,sp,#16 // cmdline argv[0]  [skip "pid"]
        adr arg2,minus_q
        adr arg1,path_gdb
        stmdb sp!,{arg1,arg2,arg3,arg4,arg5}  // argv
        mov arg3,#0  // _envviron  BUG
        mov arg2,sp  // &argv
        do_sys7t __NR_execve
0:
        b 0b
minus_q:
        .asciz "-q"
path_gdb:
        .asciz "/usr/bin/gdb"
commands_gdb:
        .ascii "set prompt\n"  // null string prompt
        .ascii "info inferiors\n"
        .ascii "print \"r0-r7\"\n"
        .ascii "x/8xw $sp + 0x28\n"
        .ascii "print \"r8-r15\"\n"
        .ascii "x/8xw\n"
        .ascii "set $pc = *(int *)($sp + 0x64)\n"
        .ascii "print \"faulting instr\"\n"
        .ascii "x/i $pc\n"
        .ascii "print \"fault context\"\n"
        .ascii "x/15i $pc - 7*4\n"
      //.ascii "print \"intercept stack\"\n"
      //.ascii "x/76xw $sp\n"
        .ascii "set $sp = *(long *)($sp + 0x5c)\n"
        .ascii "print \"user stack\"\n"
        .ascii "x/64xw $sp\n"
        .ascii "kill\n"
        .ascii "quit 1"
        .byte 0
commands_gdb_end:
        .balign 4

// ucontext_t, mcontext_t, gregset_t, gret_t, REG_xxx:   <sys/ucontext.h>
// stack_t  <bits/types/stack_t.h>
__restore_rt:
    nop

proc_self_maps:
        .asciz "/proc/self/maps"
announce_sigaction:
        .ascii "\n\nSIGSEGV address space:\n"
end_announce_sigaction:
        .balign 4

adr_sigaction:
        mov r12,lr; mov lr,pc; mov pc,r12  // blx lr
sigsegv_sigaction:
        stmdb sp!,{arg2,arg3}  // save siginfo *, ucontext *
// print /proc/self/maps of child (same as parent: the beauty of fork())
        mov arg3,#end_announce_sigaction - announce_sigaction  // arg3 len
        adr arg2,announce_sigaction  // buf
        mov arg1,#FD_stderr
        do_sys7t __NR_write

        mov arg3,#O_RDONLY  // flags
        adr arg2,proc_self_maps  // path
        mov arg1,#FD_CWD
        do_sys7t2 __NR_openat; mov r_fd,r0  // fd_maps
BUFLEN= 4096
        sub sp,sp,#BUFLEN
loop_maps:
        mov arg3,#BUFLEN  // buflen
        mov arg2,sp  // buffer
        mov arg1,r_fd  // fd_maps
        do_sys7t __NR_read
        cmp r0,#0; beq done_maps
        mov arg3,r0  // buflen
        mov arg2,sp  // buf
        mov arg1,#FD_stderr
        do_sys7t __NR_write
        b loop_maps
done_maps:
        add sp,sp,#BUFLEN  // discard buffer
        mov arg1,r_fd; do_sys7t __NR_close
// end printing of /proc/self/maps

        mov arg1,#0; mov arg2,#0  // paranoia
        do_sys7t __NR_fork
        cmp r0,#0; beq child  // fork()
parent:
NR_exit= 1
        b parent  // spin; paused by gdb

unsimal:  // (dst, value)
        mov r2,#0
        stmdb sp!,{r2,lr}; call 0f
        ldmia sp!,{r2,lr}
        strb r2,[r0]  // terminator
        ret
0:
        mov ip,r1  // extra copy used at end
        mov r2,#0  // hi

        mov r3,r1  // copy lo
        adds r1,r1,r1,lsl #3   // 9*lo
        adc  r2,r2,r2,lsl #3   // 9*hi + C
        add  r2,r2,r3,lsr #(32 - 3)  // bits shifted from lo to hi

        mov r3,r1  // copy lo
        adds r1,r1,r1,lsl #4
        adc  r2,r2,r2,lsl #4
        add  r2,r2,r3,lsr #(32 - 4)  // * 0x99

        mov r3,r1  // copy lo
        adds r1,r1,r1,lsl #8
        adc  r2,r2,r2,lsl #8
        add  r2,r2,r3,lsr #(32 - 8)  // * 0x9999

        mov r3,r1  // copy lo
        adds r1,r1,r1,lsl #16
        adc  r2,r2,r2,lsl #16
        add  r2,r2,r3,lsr #(32 - 16)  // * 0x99999999

        subs r1,r1,ip,lsl #(32 - 1)  // - * 0x80000000
        sbc  r2,r2,ip,lsr #1         //   * 0x19999999

        adds r1,r1,ip
        adcs r1,r2,#0  // * 0x0.1999999a; r1 = quo(ip, 10); set flags
        add r2,r1,r1,lsl #2  // r2 = quo * 5
        sub r2,ip,r2,lsl #1  // rem = ip - 10 * quo

        stmdb sp!,{r2,lr}  // save rem and retaddr
        beq 1f; call 0b  // stop if 0==quo; else recurse for next remainder
1:
        ldmia sp!,{r1,lr}; add r1,r1,#'0'; strb r1,[r0],#1
        ret


zfind:
        ldr r1,[r0],#NBPW
        cmp r1,#0; bne zfind
        ret

f_expand:
#undef LINUX_ARM_CACHEFLUSH
#define NO_METHOD_CHECK 1
#include "arch/arm/v4a/nrv2b_d8.S"

// get_page_mask should never be called by _entry, because the 1st arg
// (the pointer) to upx_mmap_and_fd is 0.  But in the general case
// there must be a get_page_mask subroutine.  Return something plausible.
get_page_mask: .globl get_page_mask
        mvn r0,#0
        mov r0,r0,lsl #12
        ret

        .balign 4
upx_mmap_and_fd: .globl upx_mmap_and_fd
// section UMF_LINUX or UMF_ANDROID goes here

  section ELFMAINY
end_decompress: .globl end_decompress
        /* IDENTSTR goes here */

section ELFMAINZ
#if DEBUG  /*{*/
TRACE_BUFLEN=512
trace:
        str lr,[sp,#(-1+ 15)*4]  @ return pc; [remember: sp is not stored]
        mov r4,sp  @ &saved_r0
        sub sp,sp,#TRACE_BUFLEN
        mov r2,sp  @ output string

        mov r1,#'\n'; bl trace_hex  @ In: r0 as label
        mov r1,#'>';  strb r1,[r2],#1

        mov r5,#3  @ rows to print
L600:  @ each row
        sub r0,r4,#TRACE_BUFLEN
        sub r0,r0,sp
        mov r0,r0,lsr #2; mov r1,#'\n'; bl trace_hex  @ which block of 8

        mov r6,#8  @ words per row
L610:  @ each word
        ldr r0,[r4],#NBPW; mov r1,#' '; bl trace_hex  @ next word
        subs r6,r6,#1; bgt L610

        subs r5,r5,#1; bgt L600

        mov r0,#'\n'; strb r0,[r2],#1
        sub r2,r2,sp  @ count
        mov r1,sp  @ buf
        mov r0,#FD_stderr
#if defined(ARMEL_EABI4)  /*{*/
        mov r7,#__NR_write
        swi 0
#else  /*}{*/
        swi __NR_write
#endif  /*}*/
        add sp,sp,#TRACE_BUFLEN
        ldmia sp!,{TRACE_REGS}

trace_hex:  // In: r0=val, r1=punctuation before, r2=ptr; Uses: r3, ip
        strb r1,[r2],#1  @ punctuation
        mov r3,#NBPW*(8 -1)  @ shift count
        adr ip,hex
L620:
        mov r1,r0,lsr r3
        and r1,r1,#0xf
        ldrb r1,[ip, r1]
        strb r1,[r2],#1
        subs r3,r3,#NBPW; bge L620
        ret
hex:
        .ascii "0123456789abcdef"
        .balign 4
#endif  /*}*/

get_upxfn_path: .globl get_upxfn_path
        bkpt  // get_upx_fn_path should not be called in this phase
        ret

memcpy: .globl memcpy  // void *memcpy(void *dst, void const *src, size_t len)
        cmp r2,#0; beq 9f
        mov r4,r0  // original dst
0:
        ldrb r3,[r1],#1; sub  r2,r2,#1
        strb r3,[r0],#1; bne 0b
9:
        mov r0,r4  // return original dst
        ret

memset: .globl memset  // (dst, val, n)
        cmp r2,#0; beq 9f
        mov r3,r0  // original dst
0:
        strb r1,[r0],#1
        subs r2,r2,#1
        bne 0b
9:
        mov r0,r3  // return original dst
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
.globl read;      read:      do_sys __NR_read; ret
.globl stat;      stat:      do_sys __NR_stat; ret
.globl uname;     uname:     do_sys __NR_uname; ret
.globl unlink;    unlink:    do_sys __NR_unlink; ret
.globl write;     write:     do_sys __NR_write; ret

Psync: .globl Psync
        mvn r7,#~0; mov r7,r7,lsl #PAGE_SHIFT
        bic r7,r7,r0  // fragment
        sub r0,r0,r7
        add r1,r1,r7
        do_sys __NR_msync; ret

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

get_data:
        mov r12,lr; mov lr,pc; mov pc,r12  // blx lr
o_binfo:
        .word O_BINFO  // .int4 offset of b_info for text
cpr0: .globl cpr0
        /* { b_info={sz_unc, sz_cpr, {4 char}}, folded_loader...} */
eof:

/* vim:set ts=8 sw=8 et: */
