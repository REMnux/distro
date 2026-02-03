from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.emu.linux
import ghidra.pcode.emu.sys
import ghidra.pcode.emu.unix
import ghidra.program.model.listing
import ghidra.taint.model
import java.lang # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


class TaintFileReadsLinuxAmd64SyscallLibrary(ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibrary[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
    """
    A library for performing Taint Analysis on a Linux-amd64 program that reads from tainted files
     
     
    
    This library is not currently accessible from the UI. It can be used with scripts by overriding a
    taint emulator's userop library factory method.
     
     
    
    TODO: A means of adding and configuring userop libraries in the UI.
     
     
    
    TODO: Example scripts.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]], program: ghidra.program.model.listing.Program, user: ghidra.pcode.emu.unix.EmuUnixUser):
        ...

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]], fs: ghidra.pcode.emu.unix.EmuUnixFileSystem[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]], program: ghidra.program.model.listing.Program):
        ...


class TaintEmuUnixFileSystem(ghidra.pcode.emu.unix.AbstractEmuUnixFileSystem[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
    """
    A file system containing tainted files
    """

    class UntaintedFileContents(ghidra.pcode.emu.sys.EmuFileContents[ghidra.taint.model.TaintVec]):
        """
        A taint-contents for a file whose contents are not tainted
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ReadOnlyTaintArrayFileContents(ghidra.pcode.emu.sys.EmuFileContents[ghidra.taint.model.TaintVec]):
        """
        A taint-contents for a read-only file whose contents are completely tainted
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, filename: typing.Union[java.lang.String, str]):
            ...


    class TaintEmuUnixFile(ghidra.pcode.emu.unix.AbstractEmuUnixFile[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.taint.model.TaintVec]]):
        """
        A file whose contents have a taint piece
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, pathname: typing.Union[java.lang.String, str], mode: typing.Union[jpype.JInt, int]):
            ...

        def setTainted(self, tainted: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def putTaintedFile(self, pathname: typing.Union[java.lang.String, str], contents: jpype.JArray[jpype.JByte]):
        """
        Place a tainted file into the file system with the given contents
        
        :param java.lang.String or str pathname: the pathname of the file
        :param jpype.JArray[jpype.JByte] contents: the concrete contents of the file
        """



__all__ = ["TaintFileReadsLinuxAmd64SyscallLibrary", "TaintEmuUnixFileSystem"]
