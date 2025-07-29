/*
;  macros.S --
;
;  This file is part of the UPX executable compressor.
;
;  Copyright (C) 1996-2025 Markus Franz Xaver Johannes Oberhumer
;  Copyright (C) 1996-2025 Laszlo Molnar
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

                .altmacro
                .arm

__NR_SYSCALL_BASE = 0

#define bkpt .long 0xe7f001f0  /* reserved instr; Linux GNU eabi breakpoint */
#define bkpt_th .short 0xde01  /* reserved instr; Linux GNU eabi breakpoint */

.macro          do_sys7t2 N  // "7t2": two-byte N; clobbers r7 as a temporary
                mov r12,r7  // save r7 in ip
                mov r7,   #(\N) & 0xff  // syscall number
                orr r7,r7,#(\N) &~0xff  // high bits
                swi 0
                mov r7,r12  // restore r7 from ip
.endm
.macro          do_sys2 N  // two-byte N; clobbers 'ip' (r12), saves r7
                mov r12,r7  // save r7 in ip
                do_sys7t2 \N
                mov r7,r12  // restore r7 from ip
.endm
.macro          ret
                mov pc,lr  /* armv4 lacks 'bx'; fails for thumb interworking */
.endm

.macro          section name
                .section \name
.endm


// in thumb mode we need this S() macro hack to export a symbol which
// is used in a ldr statement
#define S(sym) .globl sym; sym: .L##sym


// vi:ts=8:et:nowrap
