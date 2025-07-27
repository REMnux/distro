from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.emu.sys
import ghidra.pcode.exec_
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class EmuUnixUser(java.lang.Object):
    """
    A simulated UNIX user
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_USER: typing.Final[EmuUnixUser]
    """
    The default (root?) user
    """

    uid: typing.Final[jpype.JInt]
    gids: typing.Final[java.util.Collection[java.lang.Integer]]

    def __init__(self, uid: typing.Union[jpype.JInt, int], gids: collections.abc.Sequence):
        """
        Construct a new user
        
        :param jpype.JInt or int uid: the user's uid
        :param collections.abc.Sequence gids: the user's gids
        """


class BytesEmuUnixFileSystem(AbstractEmuUnixFileSystem[jpype.JArray[jpype.JByte]]):
    """
    A concrete in-memory file system simulator suitable for UNIX programs
    """

    @typing.type_check_only
    class BytesEmuUnixFile(AbstractEmuUnixFile[jpype.JArray[jpype.JByte]]):
        """
        A concrete in-memory file suitable for UNIX programs
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, pathname: typing.Union[java.lang.String, str], mode: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Construct a new concrete simulated file system
        """


class EmuUnixFileSystem(java.lang.Object, typing.Generic[T]):
    """
    A simulated UNIX file system
    """

    class OpenFlag(java.lang.Enum[EmuUnixFileSystem.OpenFlag]):
        """
        Open flags as defined by the simulator
         
         
        
        See a UNIX manual for the exact meaning of each.
        """

        class_: typing.ClassVar[java.lang.Class]
        O_RDONLY: typing.Final[EmuUnixFileSystem.OpenFlag]
        O_WRONLY: typing.Final[EmuUnixFileSystem.OpenFlag]
        O_RDWR: typing.Final[EmuUnixFileSystem.OpenFlag]
        O_CREAT: typing.Final[EmuUnixFileSystem.OpenFlag]
        O_TRUNC: typing.Final[EmuUnixFileSystem.OpenFlag]
        O_APPEND: typing.Final[EmuUnixFileSystem.OpenFlag]

        @staticmethod
        def isRead(flags: collections.abc.Sequence) -> bool:
            """
            Check if the given flags indicate open for reading
            
            :param collections.abc.Sequence flags: the flags
            :return: true for reading
            :rtype: bool
            """

        @staticmethod
        def isWrite(flags: collections.abc.Sequence) -> bool:
            """
            Check if the given flags indicate open for writing
            
            :param collections.abc.Sequence flags: the flags
            :return: true for writing
            :rtype: bool
            """

        @staticmethod
        @typing.overload
        def set(*flags: EmuUnixFileSystem.OpenFlag) -> java.util.Set[EmuUnixFileSystem.OpenFlag]:
            """
            Construct a set of flags
            
            :param jpype.JArray[EmuUnixFileSystem.OpenFlag] flags: the flags
            :return: the set
            :rtype: java.util.Set[EmuUnixFileSystem.OpenFlag]
            """

        @staticmethod
        @typing.overload
        def set(flags: collections.abc.Sequence) -> java.util.Set[EmuUnixFileSystem.OpenFlag]:
            """
            Construct a set of flags
            
            :param collections.abc.Sequence flags: the flags
            :return: the set
            :rtype: java.util.Set[EmuUnixFileSystem.OpenFlag]
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> EmuUnixFileSystem.OpenFlag:
            ...

        @staticmethod
        def values() -> jpype.JArray[EmuUnixFileSystem.OpenFlag]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def createOrGetFile(self, pathname: typing.Union[java.lang.String, str], mode: typing.Union[jpype.JInt, int]) -> EmuUnixFile[T]:
        """
        Get the named file, creating it if it doesn't already exist
         
         
        
        This is accessed by the emulator user, not the target program.
        
        :param java.lang.String or str pathname: the pathname of the requested file
        :param jpype.JInt or int mode: the mode of a created file. Ignored if the file exists
        :return: the file
        :rtype: EmuUnixFile[T]
        :raises EmuIOException: if an error occurred
        """

    def getFile(self, pathname: typing.Union[java.lang.String, str]) -> EmuUnixFile[T]:
        """
        Get the named file
         
         
        
        This is accessed by the emulator user, not the target program.
        
        :param java.lang.String or str pathname: the pathname of the requested file
        :return: the file, or ``null`` if it doesn't exist
        :rtype: EmuUnixFile[T]
        :raises EmuIOException: if an error occurred
        """

    def newFile(self, pathname: typing.Union[java.lang.String, str], mode: typing.Union[jpype.JInt, int]) -> EmuUnixFile[T]:
        """
        A factory for constructing a new file (without adding it to the file system)
        
        :param java.lang.String or str pathname: the path of the file
        :param jpype.JInt or int mode: the mode of the new file
        :return: the new file
        :rtype: EmuUnixFile[T]
        :raises EmuIOException: if the file cannot be constructed
        """

    def open(self, pathname: typing.Union[java.lang.String, str], flags: java.util.Set[EmuUnixFileSystem.OpenFlag], user: EmuUnixUser, mode: typing.Union[jpype.JInt, int]) -> EmuUnixFile[T]:
        """
        Open the requested file according to the given flags and user
         
         
        
        This is generally accessed by the target program via a :obj:`DefaultEmuUnixFileHandle`.
        
        :param java.lang.String or str pathname: the pathname of the requested file
        :param java.util.Set[EmuUnixFileSystem.OpenFlag] flags: the requested open flags
        :param EmuUnixUser user: the user making the request
        :param jpype.JInt or int mode: the mode to assign the file, if created. Otherwise ignored
        :return: the file
        :rtype: EmuUnixFile[T]
        :raises EmuIOException: if an error occurred, e.g., file not found, or access denied
        """

    def putFile(self, pathname: typing.Union[java.lang.String, str], file: EmuUnixFile[T]):
        """
        Place the given file at the given location
         
         
        
        This is accessed by the emulator user, not the target program. If the file already exists, it
        is replaced silently.
        
        :param java.lang.String or str pathname: the pathname of the file
        :param EmuUnixFile[T] file: the file, presumably having the same pathname
        :raises EmuIOException: if an error occurred
        """

    def unlink(self, pathname: typing.Union[java.lang.String, str], user: EmuUnixUser):
        """
        Remove the file at the given location
         
         
        
        TODO: Separate the user-facing routine from the target-facing routine.
         
         
        
        If the file does not exist, this has no effect.
        
        :param java.lang.String or str pathname: the pathname of the file to unlink
        :param EmuUnixUser user: the user requesting the unlink
        :raises EmuIOException: if an error occurred
        """

    @property
    def file(self) -> EmuUnixFile[T]:
        ...


class DefaultEmuUnixFileHandle(EmuUnixFileDescriptor[T], typing.Generic[T]):
    """
    A file descriptor associated with a file on a simulated UNIX file system
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], cSpec: ghidra.program.model.lang.CompilerSpec, file: EmuUnixFile[T], flags: java.util.Set[EmuUnixFileSystem.OpenFlag], user: EmuUnixUser):
        """
        Construct a new handle on the given file
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.program.model.lang.CompilerSpec cSpec: the ABI of the target platform
        :param EmuUnixFile[T] file: the file opened by this handle
        :param java.util.Set[EmuUnixFileSystem.OpenFlag] flags: the user-specified flags, as defined by the simulator
        :param EmuUnixUser user: the user that opened the file
        
        .. seealso::
        
            | :obj:`AbstractEmuUnixSyscallUseropLibrary.createHandle(EmuUnixFile, int)`
        """

    def checkReadable(self):
        """
        Check if the file is readable, throwing :obj:`EmuIOException` if not
        """

    def checkWritable(self):
        """
        Check if the file is writable, throwing :obj:`EmuIOException` if not
        """

    def getFile(self) -> EmuUnixFile[T]:
        """
        Get the file opened to this handle
        
        :return: the file
        :rtype: EmuUnixFile[T]
        """

    @property
    def file(self) -> EmuUnixFile[T]:
        ...


class AbstractStreamEmuUnixFileHandle(EmuUnixFileDescriptor[T], typing.Generic[T]):
    """
    An abstract file descriptor having no "offset," typically for stream-like files
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], cSpec: ghidra.program.model.lang.CompilerSpec):
        """
        Construct a new handle
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param ghidra.program.model.lang.CompilerSpec cSpec: the ABI of the target platform
        
        .. seealso::
        
            | :obj:`AbstractEmuUnixSyscallUseropLibrary.createHandle(EmuUnixFile, int)`
        """


class AbstractEmuUnixSyscallUseropLibrary(ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary[T], typing.Generic[T]):
    """
    An abstract library of UNIX system calls, suitable for use with any processor
     
     
    
    See the UNIX manual pages for more information about each specific system call, error numbers,
    etc.
     
     
    
    TODO: The rest of the system calls common to UNIX.
    """

    class Errno(java.lang.Enum[AbstractEmuUnixSyscallUseropLibrary.Errno]):
        """
        The errno values as defined by the OS simulator
        """

        class_: typing.ClassVar[java.lang.Class]
        EBADF: typing.Final[AbstractEmuUnixSyscallUseropLibrary.Errno]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AbstractEmuUnixSyscallUseropLibrary.Errno:
            ...

        @staticmethod
        def values() -> jpype.JArray[AbstractEmuUnixSyscallUseropLibrary.Errno]:
            ...


    @typing.type_check_only
    class UnixStructuredPart(ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary.StructuredPart):
        """
        System calls defined using Structured Sleigh
        """

        class_: typing.ClassVar[java.lang.Class]

        def unix_readv(self, in_fd: ghidra.pcode.struct.StructuredSleigh.Var, in_iovec: ghidra.pcode.struct.StructuredSleigh.Var, in_iovcnt: ghidra.pcode.struct.StructuredSleigh.Var):
            """
            The UNIX ``readv`` system call
            
            :param ghidra.pcode.struct.StructuredSleigh.Var in_fd: the file descriptor
            :param ghidra.pcode.struct.StructuredSleigh.Var in_iovec: pointer to the vector of buffers
            :param ghidra.pcode.struct.StructuredSleigh.Var in_iovcnt: the number of buffers
            """

        def unix_writev(self, in_fd: ghidra.pcode.struct.StructuredSleigh.Var, in_iovec: ghidra.pcode.struct.StructuredSleigh.Var, in_iovcnt: ghidra.pcode.struct.StructuredSleigh.Var):
            """
            The UNIX ``writev`` system call
            
            :param ghidra.pcode.struct.StructuredSleigh.Var in_fd: the file descriptor
            :param ghidra.pcode.struct.StructuredSleigh.Var in_iovec: pointer to the vector of buffers
            :param ghidra.pcode.struct.StructuredSleigh.Var in_iovcnt: the number of buffers
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program):
        """
        Construct a new library
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param EmuUnixFileSystem[T] fs: the file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing the syscall definitions and conventions, likely the
                    target program
        """

    @typing.overload
    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], fs: EmuUnixFileSystem[T], program: ghidra.program.model.listing.Program, user: EmuUnixUser):
        """
        Construct a new library
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine emulating the hardware
        :param EmuUnixFileSystem[T] fs: a file system to export to the user-space program
        :param ghidra.program.model.listing.Program program: a program containing the syscall definitions and conventions, likely the
                    target program
        :param EmuUnixUser user: the "current user" to simulate
        """

    def putDescriptor(self, fd: typing.Union[jpype.JInt, int], desc: EmuUnixFileDescriptor[T]) -> EmuUnixFileDescriptor[T]:
        """
        Put a descriptor into the process' open file handles
        
        :param jpype.JInt or int fd: the file descriptor value
        :param EmuUnixFileDescriptor[T] desc: the simulated descriptor (handle, console, etc.)
        :return: the previous descriptor, which probably ought to be ``null``
        :rtype: EmuUnixFileDescriptor[T]
        """

    def unix_close(self, fd: T) -> T:
        """
        The UNIX ``close`` system call
        
        :param T fd: the file descriptor
        :return: 0 for success
        :rtype: T
        """

    def unix_exit(self, status: T) -> T:
        """
        The UNIX ``exit`` system call
         
         
        
        This just throws an exception, which the overall simulator or script should catch.
        
        :param T status: the status code
        :return: never
        :rtype: T
        :raises EmuProcessExitedException: always
        """

    def unix_group_exit(self, status: T):
        """
        The UNIX ``group_exit`` system call
         
         
        
        This just throws an exception, which the overall simulator or script should catch.
        
        :param T status: the status code
        :raises EmuProcessExitedException: always
        """

    def unix_open(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], pathnamePtr: T, flags: T, mode: T) -> T:
        """
        The UNIX ``open`` system call
        
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: to receive the thread's state
        :param T pathnamePtr: the file's path (pointer to character string)
        :param T flags: the flags
        :param T mode: the mode
        :return: the file descriptor
        :rtype: T
        """

    def unix_read(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], fd: T, bufPtr: T, count: T) -> T:
        """
        The UNIX ``read`` system call
        
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: to receive the thread's state
        :param T fd: the file descriptor
        :param T bufPtr: the pointer to the buffer to receive the data
        :param T count: the number of bytes to read
        :return: the number of bytes successfully read
        :rtype: T
        """

    def unix_write(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], fd: T, bufPtr: T, count: T) -> T:
        """
        The UNIX ``write`` system call
        
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: to receive the thread's state
        :param T fd: the file descriptor
        :param T bufPtr: the pointer to the buffer of data to write
        :param T count: the number of bytes to write
        :return: the number of bytes successfully written
        :rtype: T
        """


class AbstractEmuUnixFileSystem(EmuUnixFileSystem[T], typing.Generic[T]):
    """
    An abstract emulated file system, exported to an emulated user-space program
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IOStreamEmuUnixFileHandle(AbstractStreamEmuUnixFileHandle[jpype.JArray[jpype.JByte]]):
    """
    A simulated file descriptor that proxies a host resource, typically a console/terminal
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]], cSpec: ghidra.program.model.lang.CompilerSpec, input: java.io.InputStream, output: java.io.OutputStream):
        """
        Construct a proxy for a host resource
         
         
        
        **WARNING:** Think carefully before proxying any host resource to a temperamental target
        program.
        
        :param ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]] machine: the machine emulating the hardware
        :param ghidra.program.model.lang.CompilerSpec cSpec: the ABI of the target platform
        :param java.io.InputStream input: the stream representing the input side of the descriptor, if applicable
        :param java.io.OutputStream output: the stream representing the output side of the descriptor, if applicable
        """

    @staticmethod
    def stderr(machine: ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]], cSpec: ghidra.program.model.lang.CompilerSpec) -> IOStreamEmuUnixFileHandle:
        """
        Construct a proxy for the host's standard error output
        
        :param ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]] machine: the machine emulating the hardware
        :param ghidra.program.model.lang.CompilerSpec cSpec: the ABI of the target platform
        :return: the proxy's handle
        :rtype: IOStreamEmuUnixFileHandle
        """

    @staticmethod
    def stdin(machine: ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]], cSpec: ghidra.program.model.lang.CompilerSpec) -> IOStreamEmuUnixFileHandle:
        """
        Construct a proxy for the host's standard input
        
        :param ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]] machine: the machine emulating the hardware
        :param ghidra.program.model.lang.CompilerSpec cSpec: the ABI of the target platform
        :return: the proxy's handle
        :rtype: IOStreamEmuUnixFileHandle
        """

    @staticmethod
    def stdout(machine: ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]], cSpec: ghidra.program.model.lang.CompilerSpec) -> IOStreamEmuUnixFileHandle:
        """
        Construct a proxy for the host's standard output
        
        :param ghidra.pcode.emu.PcodeMachine[jpype.JArray[jpype.JByte]] machine: the machine emulating the hardware
        :param ghidra.program.model.lang.CompilerSpec cSpec: the ABI of the target platform
        :return: the proxy's handle
        :rtype: IOStreamEmuUnixFileHandle
        """


class AbstractEmuUnixFile(EmuUnixFile[T], typing.Generic[T]):
    """
    An abstract file contained in an emulated file system
    
     
    
    Contrast this with :obj:`DefaultEmuUnixFileHandle`, which is a particular process's handle when
    opening the file, not the file itself.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pathname: typing.Union[java.lang.String, str], mode: typing.Union[jpype.JInt, int]):
        """
        Construct a new file
         
         
        
        TODO: Technically, a file can be hardlinked to several pathnames, but for simplicity, or for
        diagnostics, we let the file know its own original name.
        
        :param java.lang.String or str pathname: the pathname of the file
        :param jpype.JInt or int mode: the mode of the file
        
        .. seealso::
        
            | :obj:`AbstractEmuUnixFileSystem.newFile(String, int)`
        """


class EmuUnixFileDescriptor(java.lang.Object, typing.Generic[T]):
    """
    A process's handle to a file (or other resource)
    """

    class_: typing.ClassVar[java.lang.Class]
    FD_STDIN: typing.Final = 0
    """
    The default file descriptor for stdin (standard input)
    """

    FD_STDOUT: typing.Final = 1
    """
    The default file descriptor for stdout (standard output)
    """

    FD_STDERR: typing.Final = 2
    """
    The default file descriptor for stderr (standard error output)
    """


    def close(self):
        """
        Close this descriptor
        """

    def getOffset(self) -> T:
        """
        Get the current offset of the file, or 0 if not applicable
        
        :return: the offset
        :rtype: T
        """

    def read(self, buf: T) -> T:
        """
        Read from the file opened by this handle
        
        :param T buf: the destination buffer
        :return: the number of bytes read
        :rtype: T
        :raises EmuIOException: if an error occurred
        """

    def seek(self, offset: T):
        """
        See to the given offset
        
        :param T offset: the desired offset
        :raises EmuIOException: if an error occurred
        """

    def stat(self) -> EmuUnixFileStat:
        """
        Obtain the ``stat`` structure of the file opened by this handle
        """

    def write(self, buf: T) -> T:
        """
        Read into the file opened by this handle
        
        :param T buf: the source buffer
        :return: the number of bytes written
        :rtype: T
        :raises EmuIOException: if an error occurred
        """

    @property
    def offset(self) -> T:
        ...


class EmuUnixFileStat(java.lang.Object):
    """
    Collects the ``stat`` fields common to UNIX platforms
     
     
    
    See a UNIX manual for the exact meaning of each field.
     
     
    
    TODO: Should this be parameterized with T?
     
     
    
    TODO: Are these specific to Linux, or all UNIX?
    """

    class_: typing.ClassVar[java.lang.Class]
    MODE_R: typing.Final = 4
    """
    The mode bit indicating read permission
    """

    MODE_W: typing.Final = 2
    """
    The mode bit indicating write permission
    """

    MODE_X: typing.Final = 1
    """
    The mode bit indicating execute permission
    """

    st_dev: jpype.JLong
    st_ino: jpype.JLong
    st_mode: jpype.JInt
    st_nlink: jpype.JLong
    st_uid: jpype.JInt
    st_gid: jpype.JInt
    st_rdev: jpype.JLong
    st_size: jpype.JLong
    st_blksize: jpype.JLong
    st_blocks: jpype.JLong
    st_atim_sec: jpype.JLong
    st_atim_nsec: jpype.JLong
    st_mtim_sec: jpype.JLong
    st_mtim_nsec: jpype.JLong
    st_ctim_sec: jpype.JLong
    st_ctim_nsec: jpype.JLong

    def __init__(self):
        ...

    def hasPermissions(self, req: typing.Union[jpype.JInt, int], user: EmuUnixUser) -> bool:
        """
        Check if the given user has the requested permissions on the file described by this stat
        
        :param jpype.JInt or int req: the requested permissions
        :param EmuUnixUser user: the user requesting permission
        :return: true if permitted, false if denied
        :rtype: bool
        """


class EmuUnixException(ghidra.pcode.emu.sys.EmuSystemException):
    """
    An exception for errors within UNIX sytem call libraries
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], e: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], errno: typing.Union[java.lang.Integer, int]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], errno: typing.Union[java.lang.Integer, int], e: java.lang.Throwable):
        """
        Construct a new exception with an optional errno
         
         
        
        Providing an errno allows the system call dispatcher to automatically communicate errno to
        the target program. If provided, the exception will not interrupt the emulator, because the
        target program is expected to handle it. If omitted, the dispatcher simply allows the
        exception to interrupt the emulator.
        
        :param java.lang.String or str message: the message
        :param java.lang.Integer or int errno: the errno, or ``null``
        :param java.lang.Throwable e: the cause of this exception, or ``null``
        """

    def getErrno(self) -> int:
        """
        Get the errno associated with this exception
        
        :return: the errno, or ``null``
        :rtype: int
        """

    @property
    def errno(self) -> jpype.JInt:
        ...


class EmuUnixFile(java.lang.Object, typing.Generic[T]):
    """
    A simulated UNIX file
    
     
    
    Contrast this with :obj:`EmuUnixFileDescriptor`, which is a process's handle to an open file,
    not the file itself.
    """

    class_: typing.ClassVar[java.lang.Class]

    def checkReadable(self, user: EmuUnixUser):
        """
        Require the user to have read permission on this file, throwing :obj:`EmuIOException` if not
        
        :param EmuUnixUser user: the user
        """

    def checkWritable(self, user: EmuUnixUser):
        """
        Require the user to have write permission on this file, throwing :obj:`EmuIOException` if
        not
        
        :param EmuUnixUser user: the user
        """

    def getPathname(self) -> str:
        """
        Get the original pathname of this file
         
         
        
        Depending on the fidelity of the file system simulator, and the actions taken by the target
        program, the file may no longer actually exist at this path, but it ought be have been the
        pathname at some point in the file life.
        
        :return: the pathname
        :rtype: str
        """

    def getStat(self) -> EmuUnixFileStat:
        """
        Get the file's ``stat`` structure, as defined by the simulator.
        
        :return: the stat
        :rtype: EmuUnixFileStat
        """

    def isReadable(self, user: EmuUnixUser) -> bool:
        """
        Check if the given user can read this file
        
        :param EmuUnixUser user: the user
        :return: true if permitted, false otherwise
        :rtype: bool
        """

    def isWritable(self, user: EmuUnixUser) -> bool:
        """
        Check if the given user can write this file
        
        :param EmuUnixUser user: the user
        :return: true if permitted, false otherwise
        :rtype: bool
        """

    def read(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T], offset: T, buf: T) -> T:
        """
        Read contents from the file starting at the given offset into the given buffer
         
         
        
        This roughly follows the semantics of the UNIX ``read()``. While the offset and return
        value may depend on the arithmetic, the actual contents read from the file should not.
        
        :param ghidra.pcode.exec_.PcodeArithmetic[T] arithmetic: the arithmetic
        :param T offset: the offset
        :param T buf: the buffer
        :return: the number of bytes read
        :rtype: T
        """

    def truncate(self):
        """
        Erase the contents of the file
        """

    def write(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T], offset: T, buf: T) -> T:
        """
        Write contents into the file starting at the given offset from the given buffer
         
         
        
        This roughly follows the semantics of the UNIX ``write()``. While the offset and return
        value may depend on the arithmetic, the actual contents written to the file should not.
        
        :param ghidra.pcode.exec_.PcodeArithmetic[T] arithmetic: the arithmetic
        :param T offset: the offset
        :param T buf: the buffer
        :return: the number of bytes written
        :rtype: T
        """

    @property
    def readable(self) -> jpype.JBoolean:
        ...

    @property
    def stat(self) -> EmuUnixFileStat:
        ...

    @property
    def writable(self) -> jpype.JBoolean:
        ...

    @property
    def pathname(self) -> java.lang.String:
        ...



__all__ = ["EmuUnixUser", "BytesEmuUnixFileSystem", "EmuUnixFileSystem", "DefaultEmuUnixFileHandle", "AbstractStreamEmuUnixFileHandle", "AbstractEmuUnixSyscallUseropLibrary", "AbstractEmuUnixFileSystem", "IOStreamEmuUnixFileHandle", "AbstractEmuUnixFile", "EmuUnixFileDescriptor", "EmuUnixFileStat", "EmuUnixException", "EmuUnixFile"]
