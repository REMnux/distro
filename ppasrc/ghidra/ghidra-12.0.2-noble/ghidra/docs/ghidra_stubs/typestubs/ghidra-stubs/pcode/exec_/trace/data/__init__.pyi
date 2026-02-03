from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.memory
import ghidra.trace.model.property
import ghidra.trace.model.thread
import java.lang # type: ignore
import java.nio # type: ignore


L = typing.TypeVar("L")
S = typing.TypeVar("S")
T = typing.TypeVar("T")


class AbstractPcodeTraceDataAccess(InternalPcodeTraceDataAccess):
    """
    An abstract data-access shim, for either memory or registers
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], viewport: ghidra.trace.model.TraceTimeViewport):
        """
        Construct a shim
        
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform
        :param jpype.JLong or int snap: the associated snap
        :param ghidra.trace.model.TraceTimeViewport viewport: the viewport, set to the same snapshot
        """


class DefaultPcodeTracePropertyAccess(PcodeTracePropertyAccess[T], typing.Generic[T]):
    """
    The default trace-property access shim
    """

    class_: typing.ClassVar[java.lang.Class]


class PcodeTraceAccess(java.lang.Object):
    """
    A trace access shim
     
     
    
    This encapsulates the source or destination "coordinates" of a trace to simplify access to that
    trace by p-code operations. This is also meant to encapsulate certain conventions, e.g., writes
    are effective from the destination snapshot into the indefinite future, and meant to protect
    p-code executor/emulator states from future re-factorings of the Trace API.
     
     
    
    While, technically anything can be behind the shim, the default implementations are backed by a
    trace. The shim is associated with a chosen platform and snapshot. All methods are with respect
    to that platform. In particular the addresses must all be in spaces of the platform's language.
    Note that the platform may be the trace's host platform.
    """

    class_: typing.ClassVar[java.lang.Class]

    def deriveForWrite(self, snap: typing.Union[jpype.JLong, int]) -> PcodeTraceAccess:
        """
        Derive an access for writing a snapshot, where this access was the emulator's source
        
        :param jpype.JLong or int snap: the destination snapshot key
        :return: the derived access shim
        :rtype: PcodeTraceAccess
        """

    @typing.overload
    def getDataForLocalState(self, thread: ghidra.pcode.emu.PcodeThread[typing.Any], frame: typing.Union[jpype.JInt, int]) -> PcodeTraceRegistersAccess:
        """
        Get the data-access shim for use in an emulator thread's local state
        
        :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the emulator's thread
        :param jpype.JInt or int frame: the frame, usually 0
        :return: the shim
        :rtype: PcodeTraceRegistersAccess
        """

    @typing.overload
    def getDataForLocalState(self, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> PcodeTraceRegistersAccess:
        """
        Get the data-access shim for use in an emulator thread's local state
        
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread associated with the emulator's thread
        :param jpype.JInt or int frame: the frame, usually 0
        :return: the shim
        :rtype: PcodeTraceRegistersAccess
        """

    def getDataForSharedState(self) -> PcodeTraceMemoryAccess:
        """
        Get the data-access shim for use in an emulator's shared state
        
        :return: the shim
        :rtype: PcodeTraceMemoryAccess
        """

    def getDataForThreadState(self, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> PcodeTraceDataAccess:
        """
        Get the data-access shim for use in an executor having thread context
         
         
        
        **NOTE:** Do not use this shim for an emulator thread's local state. Use
        :meth:`getDataForLocalState(PcodeThread, int) <.getDataForLocalState>` instead. This shim is meant for use in
        stand-alone executors, e.g., for evaluating Sleigh expressions. Most likely, the thread is
        the active thread in the UI.
        
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread for context, if applicable, or null
        :param jpype.JInt or int frame: the frame
        :return: the shim
        :rtype: PcodeTraceDataAccess
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language of the associated platform
        
        :return: the langauge
        :rtype: ghidra.program.model.lang.Language
        """

    def newPcodeTraceThreadAccess(self, shared: PcodeTraceMemoryAccess, local: PcodeTraceRegistersAccess) -> PcodeTraceDataAccess:
        """
        Construct a new trace thread data-access shim
        
        :param PcodeTraceMemoryAccess shared: the shared (memory) state
        :param PcodeTraceRegistersAccess local: the local (register) state
        :return: the thread data-access shim
        :rtype: PcodeTraceDataAccess
        """

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def dataForSharedState(self) -> PcodeTraceMemoryAccess:
        ...


class InternalPcodeTraceDataAccess(PcodeTraceDataAccess):

    class_: typing.ClassVar[java.lang.Class]

    def getPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...

    def getPropertyOps(self, name: typing.Union[java.lang.String, str], type: java.lang.Class[T], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.property.TracePropertyMapOperations[T]:
        ...

    def getSnap(self) -> int:
        ...

    def getViewport(self) -> ghidra.trace.model.TraceTimeViewport:
        ...

    @property
    def viewport(self) -> ghidra.trace.model.TraceTimeViewport:
        ...

    @property
    def platform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...


class PcodeTracePropertyAccess(java.lang.Object, typing.Generic[T]):
    """
    A trace-property access shim for a specific property
    
    
    .. seealso::
    
        | :obj:`PcodeTraceAccess`
    
        | :obj:`PcodeTraceDataAccess`
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self, range: ghidra.program.model.address.AddressRange):
        """
        Clear the property's value across a range
        
        :param ghidra.program.model.address.AddressRange range: the range
        """

    def get(self, address: ghidra.program.model.address.Address) -> T:
        """
        Get the property's value at the given address
         
         
        
        This may search for the same property from other related data sources, e.g., from mapped
        static images.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the value, or null if not set
        :rtype: T
        """

    def getEntry(self, address: ghidra.program.model.address.Address) -> java.util.Map.Entry[ghidra.program.model.address.AddressRange, T]:
        """
        Get the property's entry at the given address
        
        :param ghidra.program.model.address.Address address: the address
        :return: the entry, or null if not set
        :rtype: java.util.Map.Entry[ghidra.program.model.address.AddressRange, T]
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def hasSpace(self, space: ghidra.program.model.address.AddressSpace) -> bool:
        """
        Check if the trace has allocated property space for the given address space
         
         
        
        This is available for optimizations when it may take effort to compute an address. If the
        space is not allocated, then no matter the offset, the property will not have a value.
        Clients can check this method to avoid the address computation, if they already know the
        address space.
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: true if there is a property space
        :rtype: bool
        """

    @typing.overload
    def put(self, address: ghidra.program.model.address.Address, value: T):
        """
        Set the property's value at the given address
         
         
        
        The value is effective for future snapshots up to but excluding the next snapshot where
        another value is set at the same address.
        
        :param ghidra.program.model.address.Address address: the address
        :param T value: the value to set
        """

    @typing.overload
    def put(self, range: ghidra.program.model.address.AddressRange, value: T):
        """
        Set the property's value at the given range
         
         
        
        The value is effective for future snapshots up to but excluding the next snapshot where
        another value is set at the same address.
        
        :param ghidra.program.model.address.AddressRange range: the range
        :param T value: the value to set
        """

    @property
    def entry(self) -> java.util.Map.Entry[ghidra.program.model.address.AddressRange, T]:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...


class PcodeTraceMemoryAccess(PcodeTraceDataAccess):
    """
    A data-access shim for a trace's memory
    """

    class_: typing.ClassVar[java.lang.Class]


class PcodeTraceRegistersAccess(PcodeTraceDataAccess):
    """
    A data-access shim for a trace's registers
    """

    class_: typing.ClassVar[java.lang.Class]

    def initializeThreadContext(self, thread: ghidra.pcode.emu.PcodeThread[typing.Any]):
        """
        Initialize the given p-code thread's context register using register context from the trace
        at the thread's program counter
         
         
        
        This is called during thread construction, after the program counter is initialized from the
        same trace thread. This will ensure that the instruction decoder starts in the same mode as
        the disassembler was for the trace.
        
        :param ghidra.pcode.emu.PcodeThread[typing.Any] thread: the thread to initialize
        """


class DefaultPcodeTraceRegistersAccess(AbstractPcodeTraceDataAccess, PcodeTraceRegistersAccess):
    """
    The default data-access shim for trace registers
    """

    class_: typing.ClassVar[java.lang.Class]


class DefaultPcodeTraceAccess(AbstractPcodeTraceAccess[DefaultPcodeTraceMemoryAccess, DefaultPcodeTraceRegistersAccess]):
    """
    The default trace access shim for a session
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], threadsSnap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform
        :param jpype.JLong or int snap: the associated snap
        :param jpype.JLong or int threadsSnap: the snap to use when finding associated threads between trace and emulator
        """

    @typing.overload
    def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform
        :param jpype.JLong or int snap: the associated snap
        """


class AbstractPcodeTraceAccess(PcodeTraceAccess, typing.Generic[S, L]):
    """
    An abstract implementation of :obj:`PcodeTraceAccess`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], threadsSnap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform
        :param jpype.JLong or int snap: the associated snap
        :param jpype.JLong or int threadsSnap: the snap to use when finding associated threads between trace and emulator
        """

    @typing.overload
    def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform
        :param jpype.JLong or int snap: the associated snap
        """


class DefaultPcodeTraceMemoryAccess(AbstractPcodeTraceDataAccess, PcodeTraceMemoryAccess):
    """
    The default data-access shim for trace memory
    """

    class_: typing.ClassVar[java.lang.Class]


class DefaultPcodeTraceThreadAccess(PcodeTraceMemoryAccess, PcodeTraceRegistersAccess):
    """
    The default data-access shim, for both memory and registers
    
     
    
    This is not designed for use with the emulator, but rather with stand-alone p-code executors,
    e.g., to evaluate a Sleigh expression. It multiplexes a given memory access shim and another
    register access shim into a single shim for use in one state piece.
    """

    class_: typing.ClassVar[java.lang.Class]


class PcodeTraceDataAccess(java.lang.Object):
    """
    A data-access shim for a trace
    
    
    .. seealso::
    
        | :obj:`PcodeTraceAccess`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBytes(self, start: ghidra.program.model.address.Address, buf: java.nio.ByteBuffer) -> int:
        """
        Read bytes from the trace
        
        :param ghidra.program.model.address.Address start: the address of the first byte to read
        :param java.nio.ByteBuffer buf: a buffer to receive the bytes
        :return: the number of bytes read
        :rtype: int
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language of the associated platform
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getPropertyAccess(self, name: typing.Union[java.lang.String, str], type: java.lang.Class[T]) -> PcodeTracePropertyAccess[T]:
        """
        Get a property-access shim for the named property
        
        :param T: the type of the property's values:param java.lang.String or str name: the name of the property
        :param java.lang.Class[T] type: the class of the property's values
        :return: the access shim
        :rtype: PcodeTracePropertyAccess[T]
        """

    def getViewportState(self, range: ghidra.program.model.address.AddressRange) -> ghidra.trace.model.memory.TraceMemoryState:
        """
        Get the composite state of an address range, using the snapshot's viewport
         
         
        
        Typically, the viewport is at most 2 snapshots deep. When reading from a captured snapshot,
        the viewport includes only the source snapshot. When reading from scratch snapshot (usually
        generated by emulation), the viewport includes that scratch snapshot and the original source
        snapshot. The :obj:`TraceMemoryState.KNOWN` address set is the union of known address sets
        among all snapshots in the viewport. If all addresses in the given range are
        :obj:`TraceMemoryState.KNOWN`, then the composite state is known. Otherwise, the composite
        state is :obj:`TraceMemoryState.UNKNOWN`.
        
        :param ghidra.program.model.address.AddressRange range: the range to check
        :return: the composite state of the range
        :rtype: ghidra.trace.model.memory.TraceMemoryState
        """

    def intersectViewKnown(self, view: ghidra.program.model.address.AddressSetView, useFullSpans: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Compute the intersection of the given address set and the set of
        :obj:`TraceMemoryState.KNOWN` or (@link :obj:`TraceMemoryState.ERROR` memory
        
        :param ghidra.program.model.address.AddressSetView view: the address set
        :param jpype.JBoolean or bool useFullSpans: how to treat the viewport; true for ever known, false for known now.
        :return: the intersection
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def putBytes(self, start: ghidra.program.model.address.Address, buf: java.nio.ByteBuffer) -> int:
        """
        Write bytes into the trace
         
         
        
        Each written byte is effective for future snapshots up to but excluding the next snapshot
        where another byte is written at the same address.
        
        :param ghidra.program.model.address.Address start: the address of the first byte to write
        :param java.nio.ByteBuffer buf: a buffer of bytes to write
        :return: the number of bytes written
        :rtype: int
        """

    def setState(self, range: ghidra.program.model.address.AddressRange, state: ghidra.trace.model.memory.TraceMemoryState):
        """
        Set the memory state of an address range
         
         
        
        The state is set only for the destination snapshot. It is *not* effective for the
        indefinite future.
        
        :param ghidra.program.model.address.AddressRange range: the range
        :param ghidra.trace.model.memory.TraceMemoryState state: the desired state
        """

    def translate(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate the given emulator address to a host/overlay address
        
        :param ghidra.program.model.address.Address address: the emulator address
        :return: the host/overlay address
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def viewportState(self) -> ghidra.trace.model.memory.TraceMemoryState:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...



__all__ = ["AbstractPcodeTraceDataAccess", "DefaultPcodeTracePropertyAccess", "PcodeTraceAccess", "InternalPcodeTraceDataAccess", "PcodeTracePropertyAccess", "PcodeTraceMemoryAccess", "PcodeTraceRegistersAccess", "DefaultPcodeTraceRegistersAccess", "DefaultPcodeTraceAccess", "AbstractPcodeTraceAccess", "DefaultPcodeTraceMemoryAccess", "DefaultPcodeTraceThreadAccess", "PcodeTraceDataAccess"]
