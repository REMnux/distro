from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pty
import java.io # type: ignore
import java.lang # type: ignore


class ConPtyParent(ConPtyEndpoint, ghidra.pty.PtyParent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, writeHandle: Handle, readHandle: Handle, pseudoConsoleHandle: PseudoConsoleHandle):
        ...


class PseudoConsoleHandle(Handle):

    @typing.type_check_only
    class PseudoConsoleState(Handle.State):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handle: com.sun.jna.platform.win32.WinNT.HANDLE):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: com.sun.jna.platform.win32.WinNT.HANDLE):
        ...

    def resize(self, rows: typing.Union[jpype.JShort, int], cols: typing.Union[jpype.JShort, int]):
        ...


class Pipe(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def close(self):
        ...

    @staticmethod
    def createPipe() -> Pipe:
        ...

    def getReadHandle(self) -> Handle:
        ...

    def getWriteHandle(self) -> Handle:
        ...

    @property
    def readHandle(self) -> Handle:
        ...

    @property
    def writeHandle(self) -> Handle:
        ...


class HandleOutputStream(java.io.OutputStream):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: Handle):
        ...


class ConPtyEndpoint(ghidra.pty.PtyEndpoint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, writeHandle: Handle, readHandle: Handle, pseudoConsoleHandle: PseudoConsoleHandle):
        ...


class ConPty(ghidra.pty.Pty):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pipeToChild: Pipe, pipeFromChild: Pipe, pseudoConsoleHandle: PseudoConsoleHandle):
        ...

    @staticmethod
    def openpty(cols: typing.Union[jpype.JShort, int], rows: typing.Union[jpype.JShort, int]) -> ConPty:
        ...


class ConPtyChild(ConPtyEndpoint, ghidra.pty.PtyChild):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, writeHandle: Handle, readHandle: Handle, pseudoConsoleHandle: PseudoConsoleHandle):
        ...


class Handle(java.lang.AutoCloseable):

    @typing.type_check_only
    class State(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: com.sun.jna.platform.win32.WinNT.HANDLE):
        ...

    def getNative(self) -> com.sun.jna.platform.win32.WinNT.HANDLE:
        ...

    @property
    def native(self) -> com.sun.jna.platform.win32.WinNT.HANDLE:
        ...


class AnsiBufferedInputStream(java.io.InputStream):

    @typing.type_check_only
    class Mode(java.lang.Enum[AnsiBufferedInputStream.Mode]):

        class_: typing.ClassVar[java.lang.Class]
        CHARS: typing.Final[AnsiBufferedInputStream.Mode]
        ESC: typing.Final[AnsiBufferedInputStream.Mode]
        CSI: typing.Final[AnsiBufferedInputStream.Mode]
        CSI_p: typing.Final[AnsiBufferedInputStream.Mode]
        CSI_Q: typing.Final[AnsiBufferedInputStream.Mode]
        OSC: typing.Final[AnsiBufferedInputStream.Mode]
        WINDOW_TITLE: typing.Final[AnsiBufferedInputStream.Mode]
        WINDOW_TITLE_ESC: typing.Final[AnsiBufferedInputStream.Mode]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AnsiBufferedInputStream.Mode:
            ...

        @staticmethod
        def values() -> jpype.JArray[AnsiBufferedInputStream.Mode]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, in_: java.io.InputStream):
        ...


class ConPtyFactory(java.lang.Enum[ConPtyFactory], ghidra.pty.PtyFactory):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ConPtyFactory]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ConPtyFactory:
        ...

    @staticmethod
    def values() -> jpype.JArray[ConPtyFactory]:
        ...


class HandleInputStream(java.io.InputStream):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ConPtyParent", "PseudoConsoleHandle", "Pipe", "HandleOutputStream", "ConPtyEndpoint", "ConPty", "ConPtyChild", "Handle", "AnsiBufferedInputStream", "ConPtyFactory", "HandleInputStream"]
