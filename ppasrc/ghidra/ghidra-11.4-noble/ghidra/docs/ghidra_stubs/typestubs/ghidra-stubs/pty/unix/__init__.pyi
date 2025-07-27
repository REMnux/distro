from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.sun.jna # type: ignore
import com.sun.jna.ptr # type: ignore
import ghidra.pty
import java.io # type: ignore
import java.lang # type: ignore


class UnixPtyParent(UnixPtyEndpoint, ghidra.pty.PtyParent):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Err(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    BARE_POSIX: typing.Final[PosixC]

    @staticmethod
    def checkLt0(result: typing.Union[jpype.JInt, int]) -> int:
        ...


class UnixPtySessionLeader(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class UnixPty(ghidra.pty.Pty):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def openpty(ioctls: PosixC.Ioctls) -> UnixPty:
        ...


class Util(com.sun.jna.Library):
    """
    The interface for linking to ``openpty`` via jna
     
     
    
    See the UNIX manual pages
    """

    class_: typing.ClassVar[java.lang.Class]
    BARE: typing.Final[Util]
    """
    The bare library without error handling
     
     
    
    For error handling, use :obj:`.INSTANCE`, or check for errors manually, perhaps using
    :obj:`Err`.
     
     
    
    We cannot just use ``throws``:obj:`LastErrorException` to handle errors, because the
    idiom it applies is not correct for errno on UNIX. See
    https://man7.org/linux/man-pages/man3/errno.3.html, in particular:
     
        The value in errno is significant only when the return value of the call
        indicated an error (i.e., -1 from most system calls; -1 or NULL from most library functions);
        a function that succeeds is allowed to change errno.
    
     
     
    
    This actually happens on our test setup when invoking the native ``openpty`` from a
    Docker container. It returns 0, but sets errno. JNA will incorrectly interpret this as
    failure.
    """

    INSTANCE: typing.Final[Util]

    def openpty(self, amaster: com.sun.jna.ptr.IntByReference, aslave: com.sun.jna.ptr.IntByReference, name: com.sun.jna.Pointer, termp: com.sun.jna.Pointer, winp: com.sun.jna.Pointer) -> int:
        ...


class PosixC(com.sun.jna.Library):
    """
    Interface for POSIX functions in libc
     
     
    
    The functions are not documented here. Instead see the POSIX manual pages.
    """

    class Ioctls(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def TIOCSCTTY(self) -> int:
            ...

        def TIOCSWINSZ(self) -> int:
            ...

        def leaderClass(self) -> java.lang.Class[UnixPtySessionLeader]:
            ...


    class Winsize(com.sun.jna.Structure):

        class ByReference(PosixC.Winsize, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        ws_row: jpype.JShort
        ws_col: jpype.JShort
        ws_xpixel: jpype.JShort
        ws_ypixel: jpype.JShort

        def __init__(self):
            ...


    class ControllingTty(com.sun.jna.Structure):

        class ByReference(PosixC.ControllingTty, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        steal: jpype.JInt

        def __init__(self):
            ...


    class Termios(com.sun.jna.Structure):

        class ByReference(PosixC.Termios, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        TCSANOW: typing.Final = 0
        ECHO: typing.Final = 8
        c_iflag: jpype.JInt
        c_oflag: jpype.JInt
        c_cflag: jpype.JInt
        c_lflag: jpype.JInt
        c_line: jpype.JByte
        c_cc: jpype.JArray[jpype.JByte]
        c_ispeed: jpype.JInt
        c_ospeed: jpype.JInt

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BARE: typing.Final[PosixC]
    """
    The bare library without error handling
    
    
    .. seealso::
    
        | :obj:`Util.BARE`
    """

    INSTANCE: typing.Final[PosixC]

    def close(self, fd: typing.Union[jpype.JInt, int]) -> int:
        ...

    def dup2(self, oldfd: typing.Union[jpype.JInt, int], newfd: typing.Union[jpype.JInt, int]) -> int:
        ...

    def execv(self, path: typing.Union[java.lang.String, str], argv: jpype.JArray[java.lang.String]) -> int:
        ...

    def ioctl(self, fd: typing.Union[jpype.JInt, int], cmd: typing.Union[jpype.JLong, int], *args: com.sun.jna.Pointer) -> int:
        ...

    def open(self, path: typing.Union[java.lang.String, str], mode: typing.Union[jpype.JInt, int], flags: typing.Union[jpype.JInt, int]) -> int:
        ...

    def read(self, fd: typing.Union[jpype.JInt, int], buf: com.sun.jna.Pointer, len: typing.Union[jpype.JInt, int]) -> int:
        ...

    def setsid(self) -> int:
        ...

    def strerror(self, errnum: typing.Union[jpype.JInt, int]) -> str:
        ...

    def tcgetattr(self, fd: typing.Union[jpype.JInt, int], termios_p: PosixC.Termios.ByReference) -> int:
        ...

    def tcsetattr(self, fd: typing.Union[jpype.JInt, int], optional_actions: typing.Union[jpype.JInt, int], termios_p: PosixC.Termios.ByReference) -> int:
        ...

    def write(self, fd: typing.Union[jpype.JInt, int], buf: com.sun.jna.Pointer, i: typing.Union[jpype.JInt, int]) -> int:
        ...


class UnixPtyChild(UnixPtyEndpoint, ghidra.pty.PtyChild):
    ...
    class_: typing.ClassVar[java.lang.Class]


class UnixPtyEndpoint(ghidra.pty.PtyEndpoint):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FdOutputStream(java.io.OutputStream):
    """
    An output stream that wraps a native POSIX file descriptor
     
     
    
    **WARNING:** This class makes use of jnr-ffi to invoke native functions. An invalid file
    descriptor is generally detected, but an incorrect, but valid file descriptor may cause undefined
    behavior.
    """

    class_: typing.ClassVar[java.lang.Class]


class FdInputStream(java.io.InputStream):
    """
    An input stream that wraps a native POSIX file descriptor
     
     
    
    **WARNING:** This class makes use of jnr-ffi to invoke native functions. An invalid file
    descriptor is generally detected, but an incorrect, but valid file descriptor may cause undefined
    behavior.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["UnixPtyParent", "Err", "UnixPtySessionLeader", "UnixPty", "Util", "PosixC", "UnixPtyChild", "UnixPtyEndpoint", "FdOutputStream", "FdInputStream"]
