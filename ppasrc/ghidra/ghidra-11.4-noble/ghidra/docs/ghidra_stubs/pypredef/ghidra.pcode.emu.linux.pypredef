from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.emu.unix
import ghidra.pcode.exec_
import ghidra.program.model.listing


T = typing.TypeVar("T")


class EmuLinuxAmd64SyscallUseropLibrary(AbstractEmuLinuxSyscallUseropLibrary[T], typing.Generic[T]):
    """
    A system call library simulating Linux for amd64 / x86_64
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program):
        """
        Construct the system call library for Linux-amd64
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.pcode.emu.unix.EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing syscall definitions and conventions, likely the target
                    program
        """

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program, user: ghidra.pcode.emu.unix.EmuUnixUser):
        """
        Construct the system call library for Linux-amd64
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.pcode.emu.unix.EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing syscall definitions and conventions, likely the target
                    program
        :param ghidra.pcode.emu.unix.EmuUnixUser user: the "current user" to simulate
        """


class AbstractEmuLinuxSyscallUseropLibrary(ghidra.pcode.emu.unix.AbstractEmuUnixSyscallUseropLibrary[T], typing.Generic[T]):
    """
    An abstract library of Linux system calls, suitable for use with any processor
    """

    class_: typing.ClassVar[java.lang.Class]
    O_MASK_RDWR: typing.Final = 3
    O_RDONLY: typing.Final = 0
    O_WRONLY: typing.Final = 1
    O_RDWR: typing.Final = 2
    O_CREAT: typing.Final = 64
    O_TRUNC: typing.Final = 512
    O_APPEND: typing.Final = 1024

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program):
        """
        Construct a new library
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.pcode.emu.unix.EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing the syscall definitions and conventions, likely the
                    target program
        """

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program, user: ghidra.pcode.emu.unix.EmuUnixUser):
        """
        Construct a new library
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.pcode.emu.unix.EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing the syscall definitions and conventions, likely the
                    target program
        :param ghidra.pcode.emu.unix.EmuUnixUser user: the "current user" to simulate
        """


class EmuLinuxX86SyscallUseropLibrary(AbstractEmuLinuxSyscallUseropLibrary[T], typing.Generic[T]):
    """
    A system call library simulating Linux for x86 (32-bit)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program):
        """
        Construct the system call library for Linux-x86
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.pcode.emu.unix.EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing syscall definitions and conventions, likely the target
                    program
        """

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program, user: ghidra.pcode.emu.unix.EmuUnixUser):
        """
        Construct the system call library for Linux-x86
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.pcode.emu.unix.EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing syscall definitions and conventions, likely the target
                    program
        :param ghidra.pcode.emu.unix.EmuUnixUser user: the "current user" to simulate
        """

    def swi(self, executor: ghidra.pcode.exec_.PcodeExecutor[T], library: ghidra.pcode.exec_.PcodeUseropLibrary[T], number: T) -> T:
        """
        Implement this to detect and interpret the ``INT 0x80`` instruction as the syscall
        convention
        
        :param ghidra.pcode.exec_.PcodeExecutor[T] executor: to receive the executor
        :param ghidra.pcode.exec_.PcodeUseropLibrary[T] library: to receive the userop library, presumably replete with syscalls
        :param T number: the interrupt number
        :return: the address of the fall-through, to hack the :obj:`PcodeOp.CALLIND`
        :rtype: T
        """



__all__ = ["EmuLinuxAmd64SyscallUseropLibrary", "AbstractEmuLinuxSyscallUseropLibrary", "EmuLinuxX86SyscallUseropLibrary"]
