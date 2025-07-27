from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.exec_
import ghidra.pcode.struct
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.util # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


L = typing.TypeVar("L")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class EmuSyscallLibrary(ghidra.pcode.exec_.PcodeUseropLibrary[T], typing.Generic[T]):
    """
    A library of system calls
    
     
    
    A system call library is a collection of p-code executable routines, invoked by a system call
    dispatcher. That dispatcher is represented by
    :meth:`syscall(PcodeExecutor, PcodeUseropLibrary) <.syscall>`, and is exported as a sleigh userop. If this
    interface is "mixed in" with :obj:`AnnotatedPcodeUseropLibrary`, that userop is automatically
    included in the userop library. The simplest means of implementing a syscall library is probably
    via :obj:`AnnotatedEmuSyscallUseropLibrary`. It implements this interface and extends
    :obj:`AnnotatedPcodeUseropLibrary`. In addition, it provides its own annotation system for
    exporting userops as system calls.
    """

    class SyscallPcodeUseropDefinition(ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T], typing.Generic[T]):
        """
        The :meth:`EmuSyscallLibrary.syscall(PcodeExecutor, PcodeUseropLibrary) <EmuSyscallLibrary.syscall>` method wrapped as a
        userop definition
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, syslib: EmuSyscallLibrary[T]):
            ...


    class EmuSyscallDefinition(java.lang.Object, typing.Generic[T]):
        """
        The definition of a system call
        """

        class_: typing.ClassVar[java.lang.Class]

        def invoke(self, executor: ghidra.pcode.exec_.PcodeExecutor[T], library: ghidra.pcode.exec_.PcodeUseropLibrary[T]):
            """
            Invoke the system call
            
            :param ghidra.pcode.exec_.PcodeExecutor[T] executor: the executor for the system/thread invoking the call
            :param ghidra.pcode.exec_.PcodeUseropLibrary[T] library: the complete sleigh userop library for the system
            """


    class_: typing.ClassVar[java.lang.Class]
    SYSCALL_SPACE_NAME: typing.Final = "syscall"
    SYSCALL_CONVENTION_NAME: typing.Final = "syscall"

    def getSyscallUserop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T]:
        """
        In case this is not an :obj:`AnnotatedEmuSyscallUseropLibrary` or
        :obj:`AnnotatedPcodeUseropLibrary`, get the definition of the "syscall" userop for inclusion
        in the :obj:`PcodeUseropLibrary`.
         
         
        
        Implementors may wish to override this to use a pre-constructed definition. That definition
        can be easily constructed using :obj:`SyscallPcodeUseropDefinition`.
        
        :return: the syscall userop definition
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T]
        """

    def getSyscalls(self) -> java.util.Map[java.lang.Long, EmuSyscallLibrary.EmuSyscallDefinition[T]]:
        """
        Get the map of syscalls by number
         
         
        
        Note this method will be invoked for every emulated syscall, so it should be a simple
        accessor. Any computations needed to create the map should be done ahead of time.
        
        :return: the system call map
        :rtype: java.util.Map[java.lang.Long, EmuSyscallLibrary.EmuSyscallDefinition[T]]
        """

    def handleError(self, executor: ghidra.pcode.exec_.PcodeExecutor[T], err: ghidra.pcode.exec_.PcodeExecutionException) -> bool:
        """
        Try to handle an error, usually by returning it to the user program
         
         
        
        If the particular error was not expected, it is best practice to return false, causing the
        emulator to interrupt. Otherwise, some state is set in the machine that, by convention,
        communicates the error back to the user program.
        
        :param ghidra.pcode.exec_.PcodeExecutor[T] executor: the executor for the thread that caused the error
        :param ghidra.pcode.exec_.PcodeExecutionException err: the error
        :return: true if execution can continue uninterrupted
        :rtype: bool
        """

    @staticmethod
    def loadSyscallConventionMap(program: ghidra.program.model.listing.Program) -> java.util.Map[java.lang.Long, ghidra.program.model.lang.PrototypeModel]:
        """
        Derive a syscall number to calling convention map by scraping functions in the program's
        "syscall" space.
        
        :param ghidra.program.model.listing.Program program: the program whose "syscall" space to scrape
        :return: the map of syscall number to calling convention
        :rtype: java.util.Map[java.lang.Long, ghidra.program.model.lang.PrototypeModel]
        """

    @staticmethod
    def loadSyscallFunctionMap(program: ghidra.program.model.listing.Program) -> java.util.Map[java.lang.Long, ghidra.program.model.listing.Function]:
        """
        Scrape functions from the given program's "syscall" space.
        
        :param ghidra.program.model.listing.Program program: the program
        :return: a map of syscall number to function
        :rtype: java.util.Map[java.lang.Long, ghidra.program.model.listing.Function]
        """

    @staticmethod
    @typing.overload
    def loadSyscallNumberMap(dataFileName: typing.Union[java.lang.String, str]) -> java.util.Map[java.lang.Long, java.lang.String]:
        """
        Derive a syscall number to name map from the specification in a given file.
        
        :param java.lang.String or str dataFileName: the file name to be found in a modules data directory
        :return: the map
        :rtype: java.util.Map[java.lang.Long, java.lang.String]
        :raises IOException: if the file could not be read
        """

    @staticmethod
    @typing.overload
    def loadSyscallNumberMap(program: ghidra.program.model.listing.Program) -> java.util.Map[java.lang.Long, java.lang.String]:
        """
        Derive a syscall number to name map by scraping functions in the program's "syscall" space.
        
        :param ghidra.program.model.listing.Program program: the program, likely analyzed for system calls already
        :return: the map
        :rtype: java.util.Map[java.lang.Long, java.lang.String]
        """

    def readSyscallNumber(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], reason: ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason) -> int:
        """
        Retrieve the desired system call number according to the emulated system's conventions
         
         
        
        TODO: This should go away in favor of some specification stored in the emulated program
        database. Until then, we require system-specific implementations.
        
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the executor's state
        :param ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason reason: the reason for reading state, probably :obj:`Reason.EXECUTE_READ`, but should
                    be taken from the executor
        :return: the system call number
        :rtype: int
        """

    def syscall(self, executor: ghidra.pcode.exec_.PcodeExecutor[T], library: ghidra.pcode.exec_.PcodeUseropLibrary[T]):
        """
        The entry point for executing a system call on the given executor
         
         
        
        The executor's state must already be prepared according to the relevant system calling
        conventions. This will determine the system call number, according to
        :meth:`readSyscallNumber(PcodeExecutorState, Reason) <.readSyscallNumber>`, retrieve the relevant system call
        definition, and invoke it.
        
        :param ghidra.pcode.exec_.PcodeExecutor[T] executor: the executor
        :param ghidra.pcode.exec_.PcodeUseropLibrary[T] library: the library
        """

    @property
    def syscallUserop(self) -> ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T]:
        ...

    @property
    def syscalls(self) -> java.util.Map[java.lang.Long, EmuSyscallLibrary.EmuSyscallDefinition[T]]:
        ...


class EmuSystemException(ghidra.pcode.exec_.PcodeExecutionException):
    """
    A p-code execution exception related to system simulation
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], frame: ghidra.pcode.exec_.PcodeFrame):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], frame: ghidra.pcode.exec_.PcodeFrame, cause: java.lang.Throwable):
        ...


class EmuFileContents(java.lang.Object, typing.Generic[T]):
    """
    The content store to back a simulated file
    
     
    
    TODO: Could/should this just be the same interface as an execute state? If so, we'd need to
    formalize the store interface and require one for each address space in the state. Sharing that
    interface may not be a good idea.... I think implementors can use a common realization if that
    suits them.
     
     
    
    TODO: Actually, a better idea might be to introduce an address factory with custom spaces into
    the emulator. Then a library/file could just create an address space and use the state to store
    and retrieve the file contents. Better yet, when written down, those contents and markings could
    appear in the user's trace.
    """

    class_: typing.ClassVar[java.lang.Class]

    def read(self, offset: typing.Union[jpype.JLong, int], buf: T, fileSize: typing.Union[jpype.JLong, int]) -> int:
        """
        Copy values from the file into the given buffer
        
        :param jpype.JLong or int offset: the offset in the file to read
        :param T buf: the destination buffer, whose size must be known
        :param jpype.JLong or int fileSize: the size of the file
        :return: the number of bytes (not necessarily concrete) read
        :rtype: int
        """

    def truncate(self):
        """
        Erase the contents
         
         
        
        Note that the file's size will be set to 0, so actual erasure of the contents may not be
        necessary, but if the contents are expensive to store, they ought to be disposed.
        """

    def write(self, offset: typing.Union[jpype.JLong, int], buf: T, curSize: typing.Union[jpype.JLong, int]) -> int:
        """
        Write values from the given buffer into the file
        
        :param jpype.JLong or int offset: the offset in the file to write
        :param T buf: the source buffer, whose size must be known
        :param jpype.JLong or int curSize: the current size of the file
        :return: the number of bytes (not necessarily concrete) written
        :rtype: int
        """


class EmuInvalidSystemCallException(EmuSystemException):
    """
    The emulated program invoked a system call incorrectly
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, number: typing.Union[jpype.JLong, int]):
        """
        The system call number was not valid
        
        :param jpype.JLong or int number: the system call number
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class AnnotatedEmuSyscallUseropLibrary(ghidra.pcode.exec_.AnnotatedPcodeUseropLibrary[T], EmuSyscallLibrary[T], typing.Generic[T]):
    """
    A syscall library wherein Java methods are exported via a special annotated
     
     
    
    This library is both a system call and a sleigh userop library. To export a system call, it must
    also be exported as a sleigh userop. This is more conventional, as the system call dispatcher
    does not require it, however, this library uses a wrapping technique that does require it. In
    general, exporting system calls as userops will make developers and users lives easier. To avoid
    naming collisions, system calls can be exported with customized names.
    """

    class EmuSyscall(java.lang.annotation.Annotation):
        """
        An annotation to export a method as a system call in the library.
         
         
        
        The method must also be exported in the userop library, likely via :obj:`PcodeUserop`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def value(self) -> str:
            ...


    @typing.type_check_only
    class StructuredPart(ghidra.pcode.struct.StructuredSleigh):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    SYSCALL_SPACE_NAME: typing.Final = "syscall"

    def __init__(self, machine: ghidra.pcode.emu.PcodeMachine[T], program: ghidra.program.model.listing.Program):
        """
        Construct a new library including the "syscall" userop
        
        :param ghidra.pcode.emu.PcodeMachine[T] machine: the machine using this library
        :param ghidra.program.model.listing.Program program: a program from which to derive syscall configuration, conventions, etc.
        """

    def newBoundSyscall(self, opdef: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T], convention: ghidra.program.model.lang.PrototypeModel) -> UseropEmuSyscallDefinition[T]:
        """
        Export a userop as a system call
        
        :param ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T] opdef: the userop
        :return: the syscall definition
        :rtype: UseropEmuSyscallDefinition[T]
        """


class EmuIOException(EmuInvalidSystemCallException):
    """
    The simulated system interrupted with an I/O error
     
     
    
    This exception is for I/O errors within the simulated system. If the host implementation causes a
    real :obj:`IOException`, it should *not* be wrapped in this exception unless, e.g., a
    simulated file system intends to proxy the real file system.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class UseropEmuSyscallDefinition(EmuSyscallLibrary.EmuSyscallDefinition[T], typing.Generic[T]):
    """
    A system call that is defined by delegating to a p-code userop
     
     
    
    This is essentially a wrapper of the p-code userop. Knowing the number of inputs to the userop
    and by applying the calling conventions of the platform, the wrapper aliases each parameter's
    storage to its respective parameter of the userop. The userop's output is also aliased to the
    system call's return storage, again as defined by the platform's conventions.
    
    
    .. seealso::
    
        | :obj:`AnnotatedEmuSyscallUseropLibrary`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, opdef: ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T], program: ghidra.program.model.listing.Program, convention: ghidra.program.model.lang.PrototypeModel, dtMachineWord: ghidra.program.model.data.DataType):
        """
        Construct a syscall definition
        
        :param ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T] opdef: the wrapped userop definition
        :param ghidra.program.model.listing.Program program: the program, used for storage computation
        :param ghidra.program.model.lang.PrototypeModel convention: the "syscall" calling convention
        :param ghidra.program.model.data.DataType dtMachineWord: the "pointer" data type
        
        .. seealso::
        
            | :obj:`AnnotatedEmuSyscallUseropLibrary`
        """


class PairedEmuFileContents(EmuFileContents[org.apache.commons.lang3.tuple.Pair[L, R]], typing.Generic[L, R]):
    """
    The analog of :obj:`PairedPcodeExecutorStatePiece` for simulated file contents
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, left: EmuFileContents[L], right: EmuFileContents[R]):
        """
        Create a paired file contents
        
        :param EmuFileContents[L] left: the left contents
        :param EmuFileContents[R] right: the right contents
        """


class BytesEmuFileContents(EmuFileContents[jpype.JArray[jpype.JByte]]):
    """
    A concrete in-memory bytes store for simulated file contents
     
     
    
    Note that currently, the total contents cannot exceed a Java array, so the file must remain less
    than 2GB in size.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EmuProcessExitedException(EmuSystemException):
    """
    A simulated process (or thread group) has exited
     
     
    
    The simulator should catch this exception and terminate accordingly. Continuing execution of the
    emulator beyond this exception will cause undefined behavior.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T], status: T):
        """
        Construct a process-exited exception with the given status code
         
         
        
        This will attempt to concretize the status according to the given arithmetic, for display
        purposes. The original status remains accessible via :meth:`getStatus() <.getStatus>`
        
        :param T: the type values processed by the library:param ghidra.pcode.exec_.PcodeArithmetic[T] arithmetic: the machine's arithmetic
        :param T status:
        """

    def getStatus(self) -> java.lang.Object:
        """
        Get the status code as a ``T`` of the throwing machine
        
        :return: the status
        :rtype: java.lang.Object
        """

    @staticmethod
    def tryConcereteToString(arithmetic: ghidra.pcode.exec_.PcodeArithmetic[T], status: T) -> str:
        """
        Attempt to concretize a value and convert it to hex
        
        :param T: the type of the status:param ghidra.pcode.exec_.PcodeArithmetic[T] arithmetic: the arithmetic to operate on the value
        :param T status: the status value
        :return: the hex string, or the error message
        :rtype: str
        """

    @property
    def status(self) -> java.lang.Object:
        ...



__all__ = ["EmuSyscallLibrary", "EmuSystemException", "EmuFileContents", "EmuInvalidSystemCallException", "AnnotatedEmuSyscallUseropLibrary", "EmuIOException", "UseropEmuSyscallDefinition", "PairedEmuFileContents", "BytesEmuFileContents", "EmuProcessExitedException"]
