#ifndef __PPC_REGS__  /*{*/
#define __PPC_REGS__ 1

r0= 0
r1= 1
r2= 2
r3= 3
r4= 4
r5= 5
r6= 6
r7= 7
r8= 8
r9= 9
r10= 10
r11= 11
r12= 12
r13= 13
r14= 14
r15= 15
r16= 16
r17= 17
r18= 18
r19= 19
r20= 20
r21= 21
r22= 22
r23= 23
r24= 24
r25= 25
r26= 26
r27= 27
r28= 28
r29= 29
r30= 30
r31= 31

NBPW= 8  // Number of Bytes Per Word

/* Stack pointer */
sp= 1
SZ_FRAME= 6*NBPW + 8*NBPW  // (sp,cr,lr, tmp.xlc,tmp.ld,save.toc) + spill area for a0-a7
F_TOC=    SZ_FRAME  // where is the fake TOC
SZ_FRAME= SZ_FRAME + 2*2*NBPW  // space for 2 [short] TOC entries

// http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html#REG
// r0        Volatile register used in function prologs
// r1        Stack frame pointer
// r2        TOC pointer
// r3        Volatile parameter and return value register
// r4-r10    Volatile registers used for function parameters
// r11       Volatile register used in calls by pointer and as an
//             environment pointer for languages which require one
// r12       Volatile register used for exception handling and glink code
// r13       Reserved for use as system thread ID
// r14-r31   Nonvolatile registers used for local variables
//
// CR0-CR1   Volatile condition code register fields (CR0 '.' int; CR1 '.' floating)
// CR2-CR4   Nonvolatile condition code register fields
// CR5-CR7   Volatile condition code register fields

/* Subroutine arguments; not saved by callee */
a0= r3
a1= r4
a2= r5
a3= r6
a4= r7
a5= r8
a6= r9
a7= r10

/* Scratch (temporary) registers; not saved by callee */
t1= r11
t2= r12
t3= r13

/* branch and link */
#define call bl

/* branch to link register */
#define ret  blr

/* move register */
#define movr mr

#endif  /*} __PPC_REGS__ */


/*
vi:ts=4:et:nowrap
*/

