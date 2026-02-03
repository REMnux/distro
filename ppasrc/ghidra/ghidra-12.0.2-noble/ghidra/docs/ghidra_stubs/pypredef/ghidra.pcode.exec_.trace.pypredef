from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.pcode.exec_
import ghidra.pcode.exec_.trace.data
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.memory
import ghidra.trace.model.thread
import java.lang # type: ignore
import java.math # type: ignore
import org.apache.commons.lang3.tuple # type: ignore


A = typing.TypeVar("A")
P = typing.TypeVar("P")
T = typing.TypeVar("T")


class TraceEmulationIntegration(java.lang.Enum[TraceEmulationIntegration]):
    """
    A collection of static methods for integrating an emulator with a trace.
    """

    @typing.type_check_only
    class PieceType(java.lang.Record, typing.Generic[A, T]):
        """
        The key when selecting a handler for a given piece: (address-domain, value-domain)
        """

        class_: typing.ClassVar[java.lang.Class]

        def addressDomain(self) -> java.lang.Class[A]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def forHandler(handler: TraceEmulationIntegration.PieceHandler[A, T]) -> TraceEmulationIntegration.PieceType[A, T]:
            """
            Get the key for a given handler
            
            :param A: the address domain:param T: the value domain:param TraceEmulationIntegration.PieceHandler[A, T] handler: the handler
            :return: the key
            :rtype: TraceEmulationIntegration.PieceType[A, T]
            """

        @staticmethod
        def forPiece(piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T]) -> TraceEmulationIntegration.PieceType[A, T]:
            """
            Get the key for a given piece
            
            :param A: the address domain:param T: the value domain:param ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T] piece: the piece
            :return: the key
            :rtype: TraceEmulationIntegration.PieceType[A, T]
            """

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def valueDomain(self) -> java.lang.Class[T]:
            ...


    class Writer(ghidra.pcode.emu.PcodeEmulationCallbacks[java.lang.Object]):
        """
        The primary mechanism for integrating emulators and traces
         
         
        
        This implements callbacks for the emulator and provides a method for recording logged writes
        after some number of emulation steps. The client must pass this writer in as the callbacks
        and then later invoke :meth:`writeDown(PcodeTraceAccess) <.writeDown>`. This also permits the addition of
        state piece handlers via :meth:`putHandler(PieceHandler) <.putHandler>`, should the emulator be operating
        on other value domains.
        """

        class_: typing.ClassVar[java.lang.Class]

        def callbacks(self) -> ghidra.pcode.emu.PcodeEmulationCallbacks[T]:
            """
            Cast this writer to fit the emulator's value domain
             
             
            
            Use this as the callbacks parameter when constructing the trace-integrated emulator. We
            assert this cast is safe, because none of the callbacks actually depend on the emulator's
            value domain. Instead, the states are accessed generically and invocations doled out to
            respective :obj:`PieceHandler`s based on their applicable domain types.
            
            :param T: the emulator's value domain:return: this
            :rtype: ghidra.pcode.emu.PcodeEmulationCallbacks[T]
            """

        def putHandler(self, handler: TraceEmulationIntegration.PieceHandler[typing.Any, typing.Any]):
            """
            Add or replace a handler
             
             
            
            The handler must identify the address and value domains for which it is applicable. If
            there is already a handler for the same domains, the old handler is replaced by this one.
            Otherwise, this handler is added without removing any others. The handler is invoked if
            and only if the emulator's state contains a piece for the same domains. Otherwise, the
            handler may be silently ignored.
            
            :param TraceEmulationIntegration.PieceHandler[typing.Any, typing.Any] handler: the handler
            """

        @typing.overload
        def writeDown(self, into: ghidra.pcode.exec_.trace.data.PcodeTraceAccess):
            """
            Record state changes into the trace via the given access shim
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceAccess into: the access shim
            """

        @typing.overload
        def writeDown(self, snap: typing.Union[jpype.JLong, int]):
            """
            Record state changes into the trace at the given snapshot.
             
             
            
            The destination trace is the same as from the source access shim.
            
            :param jpype.JLong or int snap: the destination snapshot key
            """


    class PieceHandler(java.lang.Object, typing.Generic[A, T]):
        """
        The handler for a specific piece within an emulator's (or executor's) state.
        
        
        .. seealso::
        
            | :obj:`PcodeExecutorStatePiece`
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[TraceEmulationIntegration.PieceHandler[typing.Any, typing.Any]]
        """
        A handler that does nothing
        """


        def abstractReadUninit(self, acc: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess, thread: ghidra.pcode.emu.PcodeThread[typing.Any], piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T], space: ghidra.program.model.address.AddressSpace, offset: A, length: typing.Union[jpype.JInt, int]) -> int:
            """
            An uninitialized portion of a state piece is being read (abstract addressing).
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess acc: the trace access shim for the relevant state (shared or local)
            :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the thread, if applicable. This is null if either the state being accessed
                        is the emulator's shared state, or if the state is bound to a plain
                        :obj:`PcodeExecutor`.
            :param ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T] piece: the state piece being handled
            :param ghidra.program.model.address.AddressSpace space: the address space
            :param A offset: the offset at the start of the uninitialized portion
            :param jpype.JInt or int length: the size in bytes of the uninitialized portion
            :return: the number of bytes just initialized, typically 0 or ``length``
            :rtype: int
            
            .. seealso::
            
                | :obj:`PcodeEmulationCallbacks.readUninitialized(PcodeThread, PcodeExecutorStatePiece,
                AddressSpace, Object, int)`
            """

        def abstractWritten(self, acc: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess, written: ghidra.program.model.address.AddressSet, thread: ghidra.pcode.emu.PcodeThread[typing.Any], piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T], space: ghidra.program.model.address.AddressSpace, offset: A, length: typing.Union[jpype.JInt, int], value: T):
            """
            Data was written (abstract addressing).
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess acc: the trace access shim for the relevant state (shared or local)
            :param ghidra.program.model.address.AddressSet written: the :obj:`Writer`'s current log of written addresses (mutable).
                        Typically, this is not accessed but rather passed to delegate methods.
            :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the thread, if applicable. This is null if either the state being accessed
                        is the emulator's shared state, or if the state is bound to a plain
                        :obj:`PcodeExecutor`.
            :param ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T] piece: the state piece being handled
            :param ghidra.program.model.address.AddressSpace space: the address space
            :param A offset: the offset of the start of the write
            :param jpype.JInt or int length: the size in bytes of the write
            :param T value: the value written
            
            .. seealso::
            
                | :obj:`PcodeEmulationCallbacks.dataWritten(PcodeThread, PcodeExecutorStatePiece,
                AddressSpace, Object, int, Object)`
            """

        def dataWritten(self, acc: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess, written: ghidra.program.model.address.AddressSet, thread: ghidra.pcode.emu.PcodeThread[typing.Any], piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T], address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], value: T) -> bool:
            """
            Data was written (concrete addressing).
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess acc: the trace access shim for the relevant state (shared or local)
            :param ghidra.program.model.address.AddressSet written: the :obj:`Writer`'s current log of written addresses (mutable).
                        Typically, this is not accessed but rather passed to delegate methods.
            :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the thread, if applicable. This is null if either the state being accessed
                        is the emulator's shared state, or if the state is bound to a plain
                        :obj:`PcodeExecutor`.
            :param ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T] piece: the state piece being handled
            :param ghidra.program.model.address.Address address: the start address of the write
            :param jpype.JInt or int length: the size in bytes of the write
            :param T value: the value written
            :return: true to prevent the :obj:`Writer` from updating its log.
            :rtype: bool
            
            .. seealso::
            
                | :obj:`PcodeEmulationCallbacks.dataWritten(PcodeThread, PcodeExecutorStatePiece, Address,
                int, Object)`
            """

        def getAddressDomain(self) -> java.lang.Class[A]:
            """
            Get the address domain this can handle
            
            :return: the address domain
            :rtype: java.lang.Class[A]
            """

        def getValueDomain(self) -> java.lang.Class[T]:
            """
            Get the value domain this can handle
            
            :return: the value domain
            :rtype: java.lang.Class[T]
            """

        def readUninitialized(self, acc: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess, thread: ghidra.pcode.emu.PcodeThread[typing.Any], piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T], set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
            """
            An uninitialized portion of a state piece is being read (concrete addressing).
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess acc: the trace access shim for the relevant state (shared or local)
            :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the thread, if applicable. This is null if either the state being accessed
                        is the emulator's shared state, or if the state is bound to a plain
                        :obj:`PcodeExecutor`.
            :param ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T] piece: the state piece being handled
            :param ghidra.program.model.address.AddressSetView set: the uninitialized portion required
            :return: the addresses in ``set`` that remain uninitialized
            :rtype: ghidra.program.model.address.AddressSetView
            
            .. seealso::
            
                | :obj:`PcodeEmulationCallbacks.readUninitialized(PcodeThread, PcodeExecutorStatePiece,
                AddressSetView)`
            """

        def writeDown(self, into: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess, thread: ghidra.pcode.emu.PcodeThread[typing.Any], piece: ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T], written: ghidra.program.model.address.AddressSetView):
            """
            Serialize a given portion of the state to the trace database.
             
             
            
            The "given portion" refers to the address set provided in ``written``. Pieces may
            also have state assigned to abstract addresses. In such cases, it is up to the handler to
            track what has been written.
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess into: the destination trace access
            :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the thread associated with the piece's state
            :param ghidra.pcode.exec_.PcodeExecutorStatePiece[A, T] piece: the source state piece
            :param ghidra.program.model.address.AddressSetView written: the portion that is known to have been written
            """

        @property
        def valueDomain(self) -> java.lang.Class[T]:
            ...

        @property
        def addressDomain(self) -> java.lang.Class[A]:
            ...


    @typing.type_check_only
    class VoidPieceHandler(java.lang.Enum[TraceEmulationIntegration.VoidPieceHandler], TraceEmulationIntegration.PieceHandler[java.lang.Void, java.lang.Void]):
        """
        An implementation of :obj:`PieceHandler` that does nothing.
        
        
        .. admonition:: Implementation Note
        
            This is the object returned when a handler is not found for a given piece. It
            removes the need for a null check.
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[TraceEmulationIntegration.VoidPieceHandler]
        """
        The handler that does nothing
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEmulationIntegration.VoidPieceHandler:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceEmulationIntegration.VoidPieceHandler]:
            ...


    class BytesPieceHandler(TraceEmulationIntegration.PieceHandler[jpype.JArray[jpype.JByte], jpype.JArray[jpype.JByte]]):
        """
        A handler that implements the lazy-read-writer-later pattern of trace integration for a
        concrete emulator's bytes.
        """

        class_: typing.ClassVar[java.lang.Class]
        CHUNK_SIZE: typing.Final = 4096
        """
        The maximum number of bytes to buffer at a time
        """


        def __init__(self):
            ...


    class ImmediateBytesPieceHandler(TraceEmulationIntegration.BytesPieceHandler):
        """
        A handler that implements the lazy-read-write-immediately pattern of trace integration for a
        concrete emulator's bytes.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class AbstractPropertyBasedPieceHandler(TraceEmulationIntegration.PieceHandler[A, T], typing.Generic[A, T, P]):
        """
        An abstract implementation of :obj:`PieceHandler` that seeks to simplify integration of
        abstract domains where the state is serialized into a trace's property map.
         
         
        
        Generally, such abstract domains should follow a byte-wise access pattern. That is, it should
        be capable of reading and writing to overlapping variables. This implementation is aimed at
        that pattern. The state piece will need to implement at least
        :meth:`PcodeExecutorStatePiece.getNextEntryInternal(AddressSpace, long) <PcodeExecutorStatePiece.getNextEntryInternal>`. Each state entry
        should be serialized as an entry at the same address and size in the property map.
        Uninitialized reads should search the full range for any applicable entries. Entries may need
        to be subpieced, depending on what part of the state is already initialized.
         
         
        
        If the address domain is also abstract, the recommended pattern is to attempt to concretize
        it (see :meth:`PcodeArithmetic.toAddress(Object, AddressSpace, Purpose) <PcodeArithmetic.toAddress>`) and delegate to the
        concrete callback. Failing that, you must choose some other means of storing the state. Our
        current recommendation is to use :obj:`Address.NO_ADDRESS` in a string map, where you can
        serialize any number of (address, value) pairs. This will not work for thread-local states,
        but it is unlikely you should encounter non-concretizable addresses in a thread-local state.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class AbstractSimplePropertyBasedPieceHandler(TraceEmulationIntegration.AbstractPropertyBasedPieceHandler[A, T, P], typing.Generic[A, T, P]):
        """
        A misguided simplification of :obj:`AbstractPropertyBasedPieceHandler` that reduces the
        requirement to a simple codec.
         
         
        
        For cases where subpiecing of variables is not of concern, this simplification may suffice.
        This is usually okay for proofs of concept or very simplistic architectures. However, once
        you introduce structured/aliased registers (e.g., ``EAX`` is the lower 32 bits of
        ``RAX``), or you're dealing with off-cut memory references, you have to deal with
        subpiecing and this simplification is no longer viable.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class TraceWriter(TraceEmulationIntegration.Writer):
        """
        The implementation of :obj:`Writer` for traces.
         
         
        
        The interface is already somewhat trace-centric in that it requires
        :meth:`Writer.writeDown(PcodeTraceAccess) <Writer.writeDown>`, but those may technically do nothing (as is the
        case for the write-immediately implementations). NOTE: Perhaps we should replace the
        interface with this class (renamed to :obj:`Writer`).
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, access: ghidra.pcode.exec_.trace.data.PcodeTraceAccess):
            """
            Construct a writer which sources state from the given access shim
            
            :param ghidra.pcode.exec_.trace.data.PcodeTraceAccess access: the source access shim
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def bytesDelayedWrite(from_: ghidra.pcode.exec_.trace.data.PcodeTraceAccess) -> TraceEmulationIntegration.Writer:
        """
        Create a writer (callbacks) that lazily loads data from the given access shim.
         
         
        
        Writes are logged, but not written to the trace. Instead, the client should call
        :meth:`Writer.writeDown(PcodeTraceAccess) <Writer.writeDown>` to write the logged changes to another given
        snapshot. This is used for forking emulation from a chosen snapshot and saving the results
        into (usually scratch) snapshots. Scripts might also use this pattern to save a series of
        snapshots resulting from an emulation experiment.
        
        :param ghidra.pcode.exec_.trace.data.PcodeTraceAccess from: the access shim for lazy loads
        :return: the writer
        :rtype: TraceEmulationIntegration.Writer
        """

    @staticmethod
    @typing.overload
    def bytesImmediateWrite(access: ghidra.pcode.exec_.trace.data.PcodeTraceAccess) -> TraceEmulationIntegration.Writer:
        """
        Create a writer (callbacks) that lazily loads data and immediately writes changes to the
        given access shim.
         
         
        
        Writes are immediately stored into the trace at the same snapshot as state is sourced.
        
        :param ghidra.pcode.exec_.trace.data.PcodeTraceAccess access: the access shim for loads and stores
        :return: the writer
        :rtype: TraceEmulationIntegration.Writer
        """

    @staticmethod
    @typing.overload
    def bytesImmediateWrite(access: ghidra.pcode.exec_.trace.data.PcodeTraceAccess, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> ghidra.pcode.exec_.PcodeStateCallbacks:
        """
        Create state callbacks that lazily load data and immediately write changes to the given
        access shim.
         
         
        
        Writes are immediately stored into the trace at the same snapshot as state is sourced.
        
         
        
        Use this instead of :meth:`bytesImmediateWrite(PcodeTraceAccess) <.bytesImmediateWrite>` when interfacing directly
        with a :obj:`PcodeExecutorState` vice a :obj:`PcodeEmulator`.
        
        :param ghidra.pcode.exec_.trace.data.PcodeTraceAccess access: the access shim for loads and stores
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread for register accesses
        :param jpype.JInt or int frame: the frame for register accesses, usually 0
        :return: the callbacks
        :rtype: ghidra.pcode.exec_.PcodeStateCallbacks
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceEmulationIntegration:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceEmulationIntegration]:
        ...


class TraceMemoryStatePcodeExecutorStatePiece(ghidra.pcode.exec_.AbstractLongOffsetPcodeExecutorStatePiece[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState, ghidra.program.model.address.AddressSpace]):
    """
    The p-code execute state piece for :obj:`TraceMemoryState`
    
     
    
    This state piece is meant to be used as an auxiliary to a concrete trace-bound state. It should
    be used with :obj:`TraceMemoryStatePcodeArithmetic` as a means of computing the "state" of a
    Sleigh expression's value. It essentially works like a rudimentary taint analyzer: If any part of
    any input to the expression in tainted, i.e., not :obj:`TraceMemoryState.KNOWN`, then the result
    is :obj:`TraceMemoryState.UNKNOWN`. This is best exemplified in
    :meth:`getUnique(long, int, Reason, PcodeStateCallbacks) <.getUnique>`, though it's also exemplified in
    :meth:`getFromSpace(AddressSpace, long, int, Reason, PcodeStateCallbacks) <.getFromSpace>`.
     
     
    
    NOTE: This is backed directly by the trace rather than using :obj:`PcodeStateCallbacks`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess):
        """
        Construct a piece
        
        :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess data: the trace-data access shim
        """


class UnknownStatePcodeExecutionException(ghidra.pcode.exec_.AccessPcodeExecutionException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def getMessage(language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> str:
        ...


class AddressesReadTracePcodeExecutorStatePiece(ghidra.pcode.exec_.AbstractLongOffsetPcodeExecutorStatePiece[jpype.JArray[jpype.JByte], ghidra.program.model.address.AddressSetView, ghidra.program.model.address.AddressSpace], ghidra.pcode.exec_.PcodeExecutorStatePiece[jpype.JArray[jpype.JByte], ghidra.program.model.address.AddressSetView]):
    """
    An auxilliary state piece that reports the (trace) address ranges
     
     
    
    Except for unique spaces, sets are ignored, and gets simply echo back the range of addresses of
    the requested read. In unique spaces, the "addresses read" is treated as the value, so that
    values transiting unique space can correct have their source address ranges reported. Use this
    with :obj:`AddressesReadPcodeArithmetic` to compute the union of these ranges during Sleigh
    expression evaluation. The ranges are translated from the guest platform, if applicable, to the
    trace address. In the case of registers, the addresses are also translated to the appropriate
    overlay space, if applicable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess):
        """
        Construct the state piece
        
        :param ghidra.pcode.exec_.trace.data.PcodeTraceDataAccess data: the trace data access shim
        """


class TraceMemoryStatePcodeArithmetic(java.lang.Enum[TraceMemoryStatePcodeArithmetic], ghidra.pcode.exec_.PcodeArithmetic[ghidra.trace.model.memory.TraceMemoryState]):
    """
    The p-code arithmetic for :obj:`TraceMemoryState`
     
     
    
    This arithmetic is meant to be used as an auxiliary to a concrete arithmetic. It should be used
    with a state that knows how to load state markings from the same trace as the concrete state, so
    that it can compute the "state" of a Sleigh expression's value. It essentially works like a
    rudimentary taint analyzer: If any part of any input to the expression in tainted, i.e., not
    :obj:`TraceMemoryState.KNOWN`, then the result is :obj:`TraceMemoryState.UNKNOWN`. This is best
    exemplified in :meth:`binaryOp(int, int, int, TraceMemoryState, int, TraceMemoryState) <.binaryOp>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[TraceMemoryStatePcodeArithmetic]
    """
    The singleton instance
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceMemoryStatePcodeArithmetic:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceMemoryStatePcodeArithmetic]:
        ...


class TraceSleighUtils(java.lang.Enum[TraceSleighUtils]):
    """
    Various utilities for using Sleigh with traces
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def buildByteExecutor(platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> ghidra.pcode.exec_.PcodeExecutor[jpype.JArray[jpype.JByte]]:
        """
        Build a p-code executor that operates directly on bytes of the given trace
         
         
        
        This executor is most suitable for evaluating Sleigh expression on a given trace snapshot,
        and for manipulating or initializing variables using Sleigh code. It is generally not
        suitable for use in an emulator. For that, use :obj:`PcodeEmulator` with
        :obj:`TraceEmulationIntegration`.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the executor
        :rtype: ghidra.pcode.exec_.PcodeExecutor[jpype.JArray[jpype.JByte]]
        """

    @staticmethod
    @typing.overload
    def buildByteExecutor(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> ghidra.pcode.exec_.PcodeExecutor[jpype.JArray[jpype.JByte]]:
        """
        
        
        :param ghidra.trace.model.Trace trace: the trace whose host platform to use
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the executor
        :rtype: ghidra.pcode.exec_.PcodeExecutor[jpype.JArray[jpype.JByte]]
        
        .. seealso::
        
            | :obj:`.buildByteExecutor(TracePlatform, long, TraceThread, int)`
        """

    @staticmethod
    @typing.overload
    def buildByteWithStateExecutor(platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> ghidra.pcode.exec_.PcodeExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]]:
        """
        Build a p-code executor that operates directly on bytes and memory state of the given trace
         
         
        
        This executor is most suitable for evaluating Sleigh expressions on a given trace snapshot,
        when the client would also like to know if all variables involved are
        :obj:`TraceMemoryState.KNOWN`.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the executor
        :rtype: ghidra.pcode.exec_.PcodeExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]]
        """

    @staticmethod
    @typing.overload
    def buildByteWithStateExecutor(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> ghidra.pcode.exec_.PcodeExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]]:
        """
        
        
        :param ghidra.trace.model.Trace trace: the trace whose host platform to use
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the executor
        :rtype: ghidra.pcode.exec_.PcodeExecutor[org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]]
        
        .. seealso::
        
            | :obj:`.buildByteWithStateExecutor(TracePlatform, long, TraceThread, int)`
        """

    @staticmethod
    @typing.overload
    def evaluate(expr: ghidra.pcode.exec_.PcodeExpression, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        """
        Evaluate a compiled p-code expression on the given trace
        
        :param ghidra.pcode.exec_.PcodeExpression expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value of the expression as a big integer
        :rtype: java.math.BigInteger
        """

    @staticmethod
    @typing.overload
    def evaluate(expr: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        """
        Evaluate a Sleigh expression on the given trace
        
        :param java.lang.String or str expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value of the expression as a big integer
        :rtype: java.math.BigInteger
        """

    @staticmethod
    @typing.overload
    def evaluateBytes(expr: ghidra.pcode.exec_.PcodeExpression, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Evaluate a compiled p-code expression on the given trace
        
        :param ghidra.pcode.exec_.PcodeExpression expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value of the expression as a byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    @typing.overload
    def evaluateBytes(expr: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Evaluate a Sleigh expression on the given trace
        
        :param java.lang.String or str expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value of the expression as a byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    @typing.overload
    def evaluateBytesWithState(expr: ghidra.pcode.exec_.PcodeExpression, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]:
        """
        Evaluate a compiled p-code expression on the given trace
        
        :param ghidra.pcode.exec_.PcodeExpression expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value and state of the expression
        :rtype: org.apache.commons.lang3.tuple.Pair[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]
        """

    @staticmethod
    @typing.overload
    def evaluateBytesWithState(expr: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> java.util.Map.Entry[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]:
        """
        Evaluate a Sleigh expression on the given trace
        
        :param java.lang.String or str expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value and state of the expression
        :rtype: java.util.Map.Entry[jpype.JArray[jpype.JByte], ghidra.trace.model.memory.TraceMemoryState]
        """

    @staticmethod
    @typing.overload
    def evaluateWithState(expr: ghidra.pcode.exec_.PcodeExpression, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> org.apache.commons.lang3.tuple.Pair[java.math.BigInteger, ghidra.trace.model.memory.TraceMemoryState]:
        """
        Evaluate a compiled p-code expression on the given trace
        
        :param ghidra.pcode.exec_.PcodeExpression expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value and state of the expression
        :rtype: org.apache.commons.lang3.tuple.Pair[java.math.BigInteger, ghidra.trace.model.memory.TraceMemoryState]
        """

    @staticmethod
    @typing.overload
    def evaluateWithState(expr: typing.Union[java.lang.String, str], trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> java.util.Map.Entry[java.math.BigInteger, ghidra.trace.model.memory.TraceMemoryState]:
        """
        Evaluate a Sleigh expression on the given trace
        
        :param java.lang.String or str expr: the expression
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.trace.model.thread.TraceThread thread: the thread, required if register space is used
        :param jpype.JInt or int frame: the frame, for when register space is used
        :return: the value and state of the expression
        :rtype: java.util.Map.Entry[java.math.BigInteger, ghidra.trace.model.memory.TraceMemoryState]
        """

    @staticmethod
    def generateExpressionForRange(language: ghidra.program.model.lang.Language, range: ghidra.program.model.address.AddressRange) -> str:
        """
        Generate the expression for retrieving a memory range
         
         
        
        In general, it does not make sense to use this directly with the above evaluation methods.
        More likely, this is used in the UI to aid the user in generating an expression. From the
        API, it's much easier to access the memory state directly.
        
        :param ghidra.program.model.lang.Language language: the language
        :param ghidra.program.model.address.AddressRange range: the range
        :return: the expression
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceSleighUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceSleighUtils]:
        ...



__all__ = ["TraceEmulationIntegration", "TraceMemoryStatePcodeExecutorStatePiece", "UnknownStatePcodeExecutionException", "AddressesReadTracePcodeExecutorStatePiece", "TraceMemoryStatePcodeArithmetic", "TraceSleighUtils"]
