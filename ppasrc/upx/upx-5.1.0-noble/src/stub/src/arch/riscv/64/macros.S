/*
;  macros.S --
;
;  This file is part of the UPX executable compressor.
;
;  Copyright (C) Markus Franz Xaver Johannes Oberhumer
;  Copyright (C) Laszlo Molnar
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
;  Markus F.X.J. Oberhumer              Laszlo Molnar
;  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
;
*/

.macro          section name
                .section \name
.endm

.macro syscall num
        li a7,\num; ecall
.endm

NBPW= 8

.macro  PUSH4 a,b,c,d
        addi sp,sp,-4*NBPW
        sd \a,0*NBPW(sp)
        sd \b,1*NBPW(sp)
        sd \c,2*NBPW(sp)
        sd \d,3*NBPW(sp)
.endm

.macro POP4 a,b,c,d
        ld \a,0*NBPW(sp)
        ld \b,1*NBPW(sp)
        ld \c,2*NBPW(sp)
        ld \d,3*NBPW(sp)
        addi sp,sp,4*NBPW
.endm

.macro  PUSH3 a,b,c
        addi sp,sp,-4*NBPW
        sd \a,0*NBPW(sp)
        sd \b,1*NBPW(sp)
        sd \c,2*NBPW(sp)
.endm

.macro POP3 a,b,c
        ld \a,0*NBPW(sp)
        ld \b,1*NBPW(sp)
        ld \c,2*NBPW(sp)
        addi sp,sp,4*NBPW
.endm

.macro  PUSH2 a,b
        addi sp,sp,-2*NBPW
        sd \a,0*NBPW(sp)
        sd \b,1*NBPW(sp)
.endm

.macro POP2 a,b,c
        ld \a,0*NBPW(sp)
        ld \b,1*NBPW(sp)
        addi sp,sp,2*NBPW
.endm

.macro  PUSH1 a
        addi sp,sp,-2*NBPW
        sd \a,0*NBPW(sp)
.endm

.macro POP1 a
        ld \a,0*NBPW(sp)
        addi sp,sp,2*NBPW
.endm

.macro SUB2 dst,src
        sub \dst,\dst,\src
.endm

.macro bkpt
        ebreak
.endm

// vi:ts=8:et:nowrap
