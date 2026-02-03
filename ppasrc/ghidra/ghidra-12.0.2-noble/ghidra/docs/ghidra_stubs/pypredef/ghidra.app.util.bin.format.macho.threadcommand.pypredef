from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import java.lang # type: ignore


class ThreadCommand(ghidra.app.util.bin.format.macho.commands.LoadCommand):
    """
    Represents a thread_command structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader):
        ...

    def getInitialInstructionPointer(self) -> int:
        ...

    def getThreadState(self) -> ThreadState:
        ...

    def getThreadStateHeader(self) -> ThreadStateHeader:
        ...

    @property
    def initialInstructionPointer(self) -> jpype.JLong:
        ...

    @property
    def threadState(self) -> ThreadState:
        ...

    @property
    def threadStateHeader(self) -> ThreadStateHeader:
        ...


class DebugStateX86_64(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    dr0: jpype.JLong
    dr1: jpype.JLong
    dr2: jpype.JLong
    dr3: jpype.JLong
    dr4: jpype.JLong
    dr5: jpype.JLong
    dr6: jpype.JLong
    dr7: jpype.JLong


class ThreadStatePPC(ThreadState):

    class_: typing.ClassVar[java.lang.Class]
    PPC_THREAD_STATE: typing.Final = 1
    PPC_FLOAT_STATE: typing.Final = 2
    PPC_EXCEPTION_STATE: typing.Final = 3
    PPC_VECTOR_STATE: typing.Final = 4
    PPC_THREAD_STATE64: typing.Final = 5
    PPC_EXCEPTION_STATE64: typing.Final = 6
    THREAD_STATE_NONE: typing.Final = 7
    srr0: jpype.JLong
    """
    Instruction address register (PC)
    """

    srr1: jpype.JLong
    """
    Machine state register (supervisor)
    """

    r0: jpype.JLong
    r1: jpype.JLong
    r2: jpype.JLong
    r3: jpype.JLong
    r4: jpype.JLong
    r5: jpype.JLong
    r6: jpype.JLong
    r7: jpype.JLong
    r8: jpype.JLong
    r9: jpype.JLong
    r10: jpype.JLong
    r11: jpype.JLong
    r12: jpype.JLong
    r13: jpype.JLong
    r14: jpype.JLong
    r15: jpype.JLong
    r16: jpype.JLong
    r17: jpype.JLong
    r18: jpype.JLong
    r19: jpype.JLong
    r20: jpype.JLong
    r21: jpype.JLong
    r22: jpype.JLong
    r23: jpype.JLong
    r24: jpype.JLong
    r25: jpype.JLong
    r26: jpype.JLong
    r27: jpype.JLong
    r28: jpype.JLong
    r29: jpype.JLong
    r30: jpype.JLong
    r31: jpype.JLong
    cr: jpype.JInt
    """
    Condition register
    """

    xer: jpype.JLong
    """
    User's integer exception register
    """

    lr: jpype.JLong
    """
    Link register
    """

    ctr: jpype.JLong
    """
    Count register
    """

    mq: jpype.JLong
    """
    MQ register (601 only)
    """

    vrsave: jpype.JLong
    """
    Vector Save Register
    """



class ThreadStateARM(ThreadState):
    """
    Represents a _STRUCT_ARM_THREAD_STATE structure.
    
    
    .. seealso::
    
        | `mach/arm/_structs.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/arm/_structs.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    ARM_THREAD_STATE: typing.Final = 1
    ARM_VFP_STATE: typing.Final = 2
    ARM_EXCEPTION_STATE: typing.Final = 3
    ARM_DEBUG_STATE: typing.Final = 4
    THREAD_STATE_NONE: typing.Final = 5
    r0: jpype.JInt
    r1: jpype.JInt
    r2: jpype.JInt
    r3: jpype.JInt
    r4: jpype.JInt
    r5: jpype.JInt
    r6: jpype.JInt
    r7: jpype.JInt
    r8: jpype.JInt
    r9: jpype.JInt
    r10: jpype.JInt
    r11: jpype.JInt
    r12: jpype.JInt
    sp: jpype.JInt
    lr: jpype.JInt
    pc: jpype.JInt
    cpsr: jpype.JInt


class ThreadStateX86_32(ThreadStateX86):
    """
    Represents a _STRUCT_X86_THREAD_STATE32 structure.
    
    
    .. seealso::
    
        | `mach/i386/_structs.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/i386/_structs.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    eax: jpype.JInt
    ebx: jpype.JInt
    ecx: jpype.JInt
    edx: jpype.JInt
    edi: jpype.JInt
    esi: jpype.JInt
    ebp: jpype.JInt
    esp: jpype.JInt
    ss: jpype.JInt
    eflags: jpype.JInt
    eip: jpype.JInt
    cs: jpype.JInt
    ds: jpype.JInt
    es: jpype.JInt
    fs: jpype.JInt
    gs: jpype.JInt


class FloatStateX86_32(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ExceptionStateX86_64(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    trapno: jpype.JInt
    err: jpype.JInt
    faultvaddr: jpype.JLong


class ThreadStateHeader(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getCount(self) -> int:
        """
        Returns the count of longs in thread state.
        
        :return: the count of longs in thread state
        :rtype: int
        """

    def getFlavor(self) -> int:
        """
        Returns the flavor of thread state.
        
        :return: the flavor of thread state
        :rtype: int
        """

    @property
    def flavor(self) -> jpype.JInt:
        ...

    @property
    def count(self) -> jpype.JLong:
        ...


class ThreadStateX86_64(ThreadStateX86):
    """
    Represents a _STRUCT_X86_THREAD_STATE64 structure.
    
    
    .. seealso::
    
        | `mach/i386/_structs.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/i386/_structs.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    rax: jpype.JLong
    rbx: jpype.JLong
    rcx: jpype.JLong
    rdx: jpype.JLong
    rdi: jpype.JLong
    rsi: jpype.JLong
    rbp: jpype.JLong
    rsp: jpype.JLong
    r8: jpype.JLong
    r9: jpype.JLong
    r10: jpype.JLong
    r11: jpype.JLong
    r12: jpype.JLong
    r13: jpype.JLong
    r14: jpype.JLong
    r15: jpype.JLong
    rip: jpype.JLong
    rflags: jpype.JLong
    cs: jpype.JLong
    fs: jpype.JLong
    gs: jpype.JLong


class ThreadState(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getInstructionPointer(self) -> int:
        ...

    @property
    def instructionPointer(self) -> jpype.JLong:
        ...


class ExceptionStateX86_32(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    trapno: jpype.JInt
    err: jpype.JInt
    faultvaddr: jpype.JInt


class DebugStateX86_32(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    dr0: jpype.JInt
    dr1: jpype.JInt
    dr2: jpype.JInt
    dr3: jpype.JInt
    dr4: jpype.JInt
    dr5: jpype.JInt
    dr6: jpype.JInt
    dr7: jpype.JInt


class ThreadStateARM_64(ThreadState):
    """
    Represents a _STRUCT_ARM_THREAD_STATE64 structure.
    
    
    .. seealso::
    
        | `mach/arm/_structs.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/arm/_structs.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    ARM64_THREAD_STATE: typing.Final = 6
    x0: jpype.JLong
    x1: jpype.JLong
    x2: jpype.JLong
    x3: jpype.JLong
    x4: jpype.JLong
    x5: jpype.JLong
    x6: jpype.JLong
    x7: jpype.JLong
    x8: jpype.JLong
    x9: jpype.JLong
    x10: jpype.JLong
    x11: jpype.JLong
    x12: jpype.JLong
    x13: jpype.JLong
    x14: jpype.JLong
    x15: jpype.JLong
    x16: jpype.JLong
    x17: jpype.JLong
    x18: jpype.JLong
    x19: jpype.JLong
    x20: jpype.JLong
    x21: jpype.JLong
    x22: jpype.JLong
    x23: jpype.JLong
    x24: jpype.JLong
    x25: jpype.JLong
    x26: jpype.JLong
    x27: jpype.JLong
    x28: jpype.JLong
    fp: jpype.JLong
    lr: jpype.JLong
    sp: jpype.JLong
    pc: jpype.JLong
    cpsr: jpype.JInt
    pad: jpype.JInt


@typing.type_check_only
class ThreadStateX86(ThreadState):

    class_: typing.ClassVar[java.lang.Class]
    i386_THREAD_STATE: typing.Final = 1
    i386_FLOAT_STATE: typing.Final = 2
    i386_EXCEPTION_STATE: typing.Final = 3
    x86_THREAD_STATE32: typing.Final = 1
    x86_FLOAT_STATE32: typing.Final = 2
    x86_EXCEPTION_STATE32: typing.Final = 3
    x86_THREAD_STATE64: typing.Final = 4
    x86_FLOAT_STATE64: typing.Final = 5
    x86_EXCEPTION_STATE64: typing.Final = 6
    x86_THREAD_STATE: typing.Final = 7
    x86_FLOAT_STATE: typing.Final = 8
    x86_EXCEPTION_STATE: typing.Final = 9
    x86_DEBUG_STATE32: typing.Final = 10
    x86_DEBUG_STATE64: typing.Final = 11
    x86_DEBUG_STATE: typing.Final = 12
    THREAD_STATE_NONE: typing.Final = 13



__all__ = ["ThreadCommand", "DebugStateX86_64", "ThreadStatePPC", "ThreadStateARM", "ThreadStateX86_32", "FloatStateX86_32", "ExceptionStateX86_64", "ThreadStateHeader", "ThreadStateX86_64", "ThreadState", "ExceptionStateX86_32", "DebugStateX86_32", "ThreadStateARM_64", "ThreadStateX86"]
