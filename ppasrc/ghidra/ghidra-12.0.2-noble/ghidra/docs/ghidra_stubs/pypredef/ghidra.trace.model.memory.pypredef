from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.program
import ghidra.trace.model.stack
import ghidra.trace.model.target
import ghidra.trace.model.target.iface
import ghidra.trace.model.thread
import ghidra.util.exception
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.nio # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class TraceRegister(ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A register
     
     
    
    There are two conventions for presenting registers and their values. Both are highly recommended:
     
     
    1. In the :obj:`TraceMemoryManager`: If this convention is not implemented by the
    connector, then the trace database itself will try to convert the object-model tree presentation
    to it, because the only way to annotate data types and references in registers is to instantiate
    the appropriate register space. See the manager's documentation for how to set these up.
    NOTE: The :obj:`TraceRegisterContainer` for the relevant thread or frame
    must exist in this convention, even if the tree convention is not presented.
    2. In the :obj:`TraceObjectManager`: This convention is required when a register is not
    known to Ghidra's slaspec, which is certainly the case if the connector falls back to the
    ``DATA`` processor. It is easiest just to always present the tree. It provides some
    redundancy in case the memory-manager presentation gets broken, and it allows the user to choose
    a preferred presentation. In the tree convention, each register is presented with this interface.
    The name is taken from the object key, the length in bits is given in the attribute
    :obj:`.KEY_BITLENGTH`, and the value is given in the attribute
    :obj:`TraceObjectInterface.KEY_VALUE`. Alternatively, connectors may present registers as
    primitive children of the container.
    
     
     
    
    Some connectors may present registers in groups. To support this, there is an explicit
    :obj:`TraceRegisterContainer`. Ordinarily, the client would use the schema to detect a
    "container" of :obj:`TraceRegister`; however, that is not sufficient with groups. The root
    container (per thread or per frame) is marked as the :obj:`TraceRegisterContainer`. The
    connector may then organize the registers into groups, each group being a plain
    :obj:`TraceObject`, so long as each :obj:`TraceRegister` is a successor to the register
    container.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_BITLENGTH: typing.Final = "_length"
    KEY_STATE: typing.Final = "_state"

    def getBitLength(self, snap: typing.Union[jpype.JLong, int]) -> int:
        ...

    def getByteLength(self, snap: typing.Union[jpype.JLong, int]) -> int:
        ...

    def getName(self) -> str:
        ...

    def getState(self, snap: typing.Union[jpype.JLong, int]) -> TraceMemoryState:
        ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    def getValue(self, snap: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        ...

    def setState(self, lifespan: ghidra.trace.model.Lifespan, state: TraceMemoryState):
        ...

    def setValue(self, lifespan: ghidra.trace.model.Lifespan, value: jpype.JArray[jpype.JByte]):
        ...

    @property
    def bitLength(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def byteLength(self) -> jpype.JInt:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def state(self) -> TraceMemoryState:
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...


class TraceMemorySpace(TraceMemoryOperations):
    """
    A portion of the memory manager bound to a particular address space
     
     
    
    For most memory operations, the methods on :obj:`TraceMemoryManager` are sufficient, as they
    will automatically obtain the appropriate :obj:`TraceMemorySpace` for the address space of the
    given address or range. If many operations on the same space are anticipated, it may be slightly
    faster to bind to the space once and then perform all the operations. It is also necessary to
    bind when operating on (per-thread) register spaces
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the address space
        
        :return: the address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getCodeSpace(self, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.listing.TraceCodeSpace:
        """
        Get the code space for this memory space
         
         
        
        This is a convenience for :meth:`TraceCodeManager.getCodeSpace(AddressSpace, boolean) <TraceCodeManager.getCodeSpace>` on
        this same address space.
        
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the code space
        :rtype: ghidra.trace.model.listing.TraceCodeSpace
        """

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def codeSpace(self) -> ghidra.trace.model.listing.TraceCodeSpace:
        ...


class RegisterValueException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class TraceMemoryState(java.lang.Enum[TraceMemoryState]):

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN: typing.Final[TraceMemoryState]
    """
    The value was not observed at the snapshot
    """

    KNOWN: typing.Final[TraceMemoryState]
    """
    The value was observed at the snapshot
    """

    ERROR: typing.Final[TraceMemoryState]
    """
    The value could not be observed at the snapshot
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceMemoryState:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceMemoryState]:
        ...


class TraceMemoryOperations(java.lang.Object):
    """
    Operations for mutating memory regions, values, and state within a trace
     
     
    
    This models memory over the course of an arbitrary number of snaps. The duration between snaps is
    unspecified. However, the mapping of snaps to real time ought to be strictly monotonic.
    Observations of memory are recorded using the :meth:`putBytes(long, Address, ByteBuffer) <.putBytes>` and
    related methods. Those observations, and some related deductions can be retrieved using the
    :meth:`getBytes(long, Address, ByteBuffer) <.getBytes>` and related methods. Many of the ``get`` methods
    permit the retrieval of the most recent observations. This is useful as an observed value in
    memory is presumed unchanged until another observation is made. Observations of bytes in memory
    cause the state at the same location and snap to become :obj:`TraceMemoryState.KNOWN`. These
    states can be manipulated directly; however, this is recommended only to record read failures,
    using the state :obj:`TraceMemoryState.ERROR`. A state of ``null`` is equivalent to
    :obj:`TraceMemoryState.UNKNOWN` and indicates no observation has been made.
     
     
    
    Negative snaps may have different semantics than positive, since negative snaps are used as
    "scratch space". These snaps are not presumed to have any temporal relation to their neighbors,
    or any other snap for that matter. Clients may use the description field of the
    :obj:`TraceSnapshot` to indicate a relationship to another snap. Operations which seek the
    "most-recent" data might not retrieve anything from scratch snaps, and writing to a scratch snap
    might not cause any changes to others. Note the "integrity" of data where the memory state is not
    :obj:`TraceMemoryState.KNOWN` may be neglected to some extent. For example, writing bytes to
    snap -10 may cause bytes in snap -9 to change, where the effected range at snap -9 has state
    :obj:`TraceMemoryState.UNKNOWN`. The time semantics are not necessarily prohibited in scratch
    space, but implementations may choose cheaper semantics if desired. Clients should be wary not to
    accidentally rely on implied temporal relationships in scratch space.
    """

    class_: typing.ClassVar[java.lang.Class]

    def findBytes(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, data: java.nio.ByteBuffer, mask: java.nio.ByteBuffer, forward: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Search the given address range at the given snap for a given byte pattern
        
        :param jpype.JLong or int snap: the time to search
        :param ghidra.program.model.address.AddressRange range: the address range to search
        :param java.nio.ByteBuffer data: the values to search for
        :param java.nio.ByteBuffer mask: a mask on the bits of ``data``; or null to match all bytes exactly
        :param jpype.JBoolean or bool forward: true to return the match with the lowest address in ``range``, false for
                    the highest address.
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress reporting and canceling
        :return: the minimum address of the matched bytes, or ``null`` if not found
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getAddressesWithState(self, snap: typing.Union[jpype.JLong, int], set: ghidra.program.model.address.AddressSetView, predicate: java.util.function.Predicate[TraceMemoryState]) -> ghidra.program.model.address.AddressSetView:
        """
        Get at least the subset of addresses having state satisfying the given predicate
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.AddressSetView set: the set to examine
        :param java.util.function.Predicate[TraceMemoryState] predicate: a predicate on state to search for
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        
        .. seealso::
        
            | :obj:`.getAddressesWithState(Lifespan, AddressSetView, Predicate)`
        """

    @typing.overload
    def getAddressesWithState(self, span: ghidra.trace.model.Lifespan, set: ghidra.program.model.address.AddressSetView, predicate: java.util.function.Predicate[TraceMemoryState]) -> ghidra.program.model.address.AddressSetView:
        """
        Get at least the subset of addresses having state satisfying the given predicate
         
         
        
        The implementation may provide a larger view than requested, but within the requested set,
        only ranges satisfying the predicate may be present. Use
        :meth:`AddressSetView.intersect(AddressSetView) <AddressSetView.intersect>` with ``set`` if a strict subset is
        required.
         
         
        
        Because :obj:`TraceMemoryState.UNKNOWN` is not explicitly stored in the map, to compute the
        set of :obj:`TraceMemoryState.UNKNOWN` addresses, use the predicate
        ``state -> state != null && state != TraceMemoryState.UNKNOWN`` and subtract the result
        from ``set``.
        
        :param ghidra.trace.model.Lifespan span: the range of time
        :param ghidra.program.model.address.AddressSetView set: the set to examine
        :param java.util.function.Predicate[TraceMemoryState] predicate: a predicate on state to search for
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def getAddressesWithState(self, snap: typing.Union[jpype.JLong, int], predicate: java.util.function.Predicate[TraceMemoryState]) -> ghidra.program.model.address.AddressSetView:
        """
        Get the addresses having state satisfying the given predicate
         
         
        
        The implementation may provide a view that updates with changes. Behavior is not well defined
        for predicates testing for :obj:`TraceMemoryState.UNKNOWN`.
        
        :param jpype.JLong or int snap: the time
        :param java.util.function.Predicate[TraceMemoryState] predicate: a predicate on state to search for
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def getAddressesWithState(self, lifespan: ghidra.trace.model.Lifespan, predicate: java.util.function.Predicate[TraceMemoryState]) -> ghidra.program.model.address.AddressSetView:
        """
        Get the addresses having state satisfying the given predicate at any time in the specified
        lifespan
         
         
        
        The implementation may provide a view that updates with changes. Behavior is not well defined
        for predicates testing for :obj:`TraceMemoryState.UNKNOWN` .
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.util.function.Predicate[TraceMemoryState] predicate: a predicate on state to search for
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getBlockSize(self) -> int:
        """
        Get the block size used by internal storage.
         
         
        
        This method reveals portions of the internal storage so that clients can optimize searches.
        If the underlying implementation cannot answer this question, this returns 0.
        
        :return: the block size
        :rtype: int
        """

    @typing.overload
    def getBufferAt(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, byteOrder: java.nio.ByteOrder) -> ghidra.program.model.mem.MemBuffer:
        """
        Get a view of a particular snap as a memory buffer
         
         
        
        The bytes read by this buffer are the most recent bytes written before the given snap
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address start: the starting address
        :param java.nio.ByteOrder byteOrder: the byte ordering for this buffer
        :return: the memory buffer
        :rtype: ghidra.program.model.mem.MemBuffer
        """

    @typing.overload
    def getBufferAt(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address) -> ghidra.program.model.mem.MemBuffer:
        """
        Get a view of a particular snap as a memory buffer using the base language's byte order
        
        
        .. seealso::
        
            | :obj:`.getBufferAt(long, Address, ByteOrder)`
        """

    @typing.overload
    def getBytes(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, buf: java.nio.ByteBuffer) -> int:
        """
        Read the most recent bytes from the given snap and address
         
         
        
        This will attempt to read :meth:`ByteBuffer.remaining() <ByteBuffer.remaining>` of the most recent bytes from memory
        at the specified time and location and write them into the destination buffer ``buf``
        starting at :meth:`ByteBuffer.position() <ByteBuffer.position>`. Where bytes in memory have no defined value,
        values in the destination buffer are unspecified. The implementation may leave those bytes in
        the destination buffer unmodified, or it may write zeroes.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address start: the location
        :param java.nio.ByteBuffer buf: the destination buffer of bytes
        :return: the number of bytes read
        :rtype: int
        """

    @typing.overload
    def getBytes(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, buf: java.nio.ByteBuffer) -> int:
        """
        Get the most-recent bytes of a given register at the given time
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :param java.nio.ByteBuffer buf: the destination buffer
        :return: the number of bytes read
        :rtype: int
        """

    @typing.overload
    def getBytes(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, buf: java.nio.ByteBuffer) -> int:
        """
        Get the most-recent bytes of a given register at the given time
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :param java.nio.ByteBuffer buf: the destination buffer
        :return: the number of bytes read
        :rtype: int
        """

    def getMostRecentStateEntry(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]:
        """
        Get the entry recording the most recent state at the given snap and address
         
         
        
        The entry includes the entire entry at that snap. Parts occluded by more recent snaps are not
        subtracted from the entry's address range.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address address: the location
        :return: the entry including the entire recorded range
        :rtype: java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]
        """

    @typing.overload
    def getMostRecentStates(self, within: ghidra.trace.model.TraceAddressSnapRange) -> java.lang.Iterable[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        """
        Break a range of addresses into smaller ranges each mapped to its most recent state at the
        given time
         
         
        
        Typically ``within`` is the box whose width is the address range to break down and whose
        height is from "negative infinity" to the "current" snap.
         
         
        
        In this context, "most recent" means the latest state other than
        :obj:`TraceMemoryState.UNKNOWN`.
        
        :param ghidra.trace.model.TraceAddressSnapRange within: a box intersecting entries to consider
        :return: an iterable over the snap ranges and states
        :rtype: java.lang.Iterable[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]
        """

    @typing.overload
    def getMostRecentStates(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange) -> java.lang.Iterable[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        """
        
        
        
        .. seealso::
        
            | :obj:`.getMostRecentStates(TraceAddressSnapRange)`
        """

    def getSnapOfMostRecentChangeToBlock(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> int:
        """
        Find the internal storage block that most-recently defines the value at the given snap and
        address, and return the block's snap.
         
         
        
        This method reveals portions of the internal storage so that clients can optimize difference
        computations by eliminating corresponding ranges defined by the same block. If the underlying
        implementation cannot answer this question, this returns the given snap.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address address: the location
        :return: the most snap for the most recent containing block
        :rtype: int
        """

    @typing.overload
    def getState(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> TraceMemoryState:
        """
        Get the state of memory at a given snap and address
         
         
        
        If the location's state has not been set, the result is ``null``, which implies
        :obj:`TraceMemoryState.UNKNOWN`.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address address: the location
        :return: the state
        :rtype: TraceMemoryState
        """

    @typing.overload
    def getState(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> TraceMemoryState:
        """
        Assert that a register's range has a single state at the given snap and get that state
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register to examine
        :return: the state
        :rtype: TraceMemoryState
        :raises IllegalStateException: if the register is mapped to more than one state. See
                    :meth:`getStates(long, Register) <.getStates>`
        """

    @typing.overload
    def getState(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> TraceMemoryState:
        """
        Assert that a register's range has a single state at the given snap and get that state
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register to examine
        :return: the state
        :rtype: TraceMemoryState
        :raises IllegalStateException: if the register is mapped to more than one state. See
                    :meth:`getStates(long, Register) <.getStates>`
        """

    @typing.overload
    def getStates(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        """
        Break a range of addresses into smaller ranges each mapped to its state at the given snap
         
         
        
        Note that :obj:`TraceMemoryState.UNKNOWN` entries will not appear in the result. Gaps in the
        returned entries are implied to be :obj:`TraceMemoryState.UNKNOWN`.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.AddressRange range: the range to examine
        :return: the map of ranges to states
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]
        """

    @typing.overload
    def getStates(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        """
        Break the register's range into smaller ranges each mapped to its state at the given snap
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register to examine
        :return: the map of ranges to states
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]
        """

    @typing.overload
    def getStates(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        """
        Break the register's range into smaller ranges each mapped to its state at the given snap
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register to examine
        :return: the map of ranges to states
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace to which the memory manager belongs
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @typing.overload
    def getValue(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the most-recent value of a given register at the given time
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :return: the value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getValue(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the most-recent value of a given register at the given time
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :return: the value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getViewBytes(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, buf: java.nio.ByteBuffer) -> int:
        """
        Read the most recent bytes from the given snap and address, following schedule forks
         
         
        
        This behaves similarly to :meth:`getBytes(long, Address, ByteBuffer) <.getBytes>`, except it checks for
        the :obj:`TraceMemoryState.KNOWN` state among each involved snap range and reads the
        applicable address ranges, preferring the most recent. Where memory is never known the buffer
        is left unmodified.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address start: the location
        :param java.nio.ByteBuffer buf: the destination buffer of bytes
        :return: the number of bytes read
        :rtype: int
        """

    @typing.overload
    def getViewMostRecentStateEntry(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]:
        """
        Get the entry recording the most recent state at the given snap and address, following
        schedule forks
        
        :param jpype.JLong or int snap: the latest time to consider
        :param ghidra.program.model.address.Address address: the address
        :return: the most-recent entry
        :rtype: java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]
        """

    @typing.overload
    def getViewMostRecentStateEntry(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, predicate: java.util.function.Predicate[TraceMemoryState]) -> java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]:
        """
        Get the entry recording the most recent state since the given snap within the given range
        that satisfies a given predicate, following schedule forks
        
        :param jpype.JLong or int snap: the latest time to consider
        :param ghidra.program.model.address.AddressRange range: the range of addresses
        :param java.util.function.Predicate[TraceMemoryState] predicate: a predicate on the state
        :return: the most-recent entry
        :rtype: java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]
        """

    def getViewState(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Map.Entry[java.lang.Long, TraceMemoryState]:
        """
        Get the state of memory at a given snap and address, following schedule forks
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address address: the location
        :return: the state, and the snap where it was found
        :rtype: java.util.Map.Entry[java.lang.Long, TraceMemoryState]
        """

    @typing.overload
    def getViewValue(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the most-recent value of a given register at the given time
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :return: the value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getViewValue(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the most-recent value of a given register at the given time, following schedule forks
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :return: the value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def isKnown(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange) -> bool:
        """
        Check if a range addresses are all known
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.AddressRange range: the range to examine
        :return: true if the entire range is :obj:`TraceMemoryState.KNOWN`
        :rtype: bool
        """

    @staticmethod
    def isStateEntirely(range: ghidra.program.model.address.AddressRange, stateEntries: collections.abc.Sequence, state: TraceMemoryState) -> bool:
        """
        Check if the return value of :meth:`getStates(long, AddressRange) <.getStates>` or similar represents a
        single entry of the given state.
         
         
        
        This method returns false if there is not exactly one entry of the given state whose range
        covers the given range. As a special case, an empty collection will cause this method to
        return true iff state is :obj:`TraceMemoryState.UNKNOWN`.
        
        :param ghidra.program.model.address.AddressRange range: the range to check, usually that passed to
                    :meth:`getStates(long, AddressRange) <.getStates>`.
        :param collections.abc.Sequence stateEntries: the collection returned by :meth:`getStates(long, AddressRange) <.getStates>`.
        :param TraceMemoryState state: the expected state
        :return: true if the state matches
        :rtype: bool
        """

    def pack(self):
        """
        Optimize storage space
         
         
        
        This gives the implementation an opportunity to clean up garbage, apply compression, etc., in
        order to best use the storage space. Because memory observations can be sparse, a trace's
        memory is often compressible, and observations are not often modified or deleted, packing is
        recommended whenever the trace is saved to disk.
        """

    @typing.overload
    def putBytes(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, buf: java.nio.ByteBuffer) -> int:
        """
        Write bytes at the given snap and address
         
         
        
        This will attempt to read :meth:`ByteBuffer.remaining() <ByteBuffer.remaining>` bytes starting at
        :meth:`ByteBuffer.position() <ByteBuffer.position>` from the source buffer ``buf`` and write them into memory
        at the specified time and location. The affected region is also updated to
        :obj:`TraceMemoryState.KNOWN`. The written bytes are assumed effective for all future snaps
        up to the next write.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address start: the location
        :param java.nio.ByteBuffer buf: the source buffer of bytes
        :return: the number of bytes written
        :rtype: int
        """

    @typing.overload
    def putBytes(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, buf: java.nio.ByteBuffer) -> int:
        """
        
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register to modify
        :param java.nio.ByteBuffer buf: the buffer of bytes to write
        :return: the number of bytes written
        :rtype: int
        
        .. seealso::
        
            | :obj:`.putBytes(long, Register, ByteBuffer)`
        """

    @typing.overload
    def putBytes(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, buf: java.nio.ByteBuffer) -> int:
        """
        Write bytes at the given snap and register address
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space. In those
        cases, the assignment affects all threads.
         
         
        
        Note that bit-masked registers are not properly heeded. If the caller wishes to preserve
        non-masked bits, it must first retrieve the current value and combine it with the desired
        value. The caller must also account for any bit shift in the passed buffer. Alternatively,
        consider :meth:`setValue(long, RegisterValue) <.setValue>`.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register to modify
        :param java.nio.ByteBuffer buf: the buffer of bytes to write
        :return: the number of bytes written
        :rtype: int
        """

    def removeBytes(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, len: typing.Union[jpype.JInt, int]):
        """
        Remove bytes from the given time and location
         
         
        
        This deletes all observed bytes from the given address through length at the given snap. If
        there were no observations in the range at exactly the given snap, this has no effect. If
        there were, then those observations are removed. The next time those bytes are read, they
        will have a value from a previous snap, or no value at all. The affected region's state is
        also deleted, i.e., set to ``null``, implying :obj:`TraceMemoryState.UNKNOWN`.
         
         
        
        Note, use of this method is discouraged. The more observations within the same range that
        follow the deleted observation, the more expensive this operation typically is, since all of
        those observations may need to be updated.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address start: the location
        :param jpype.JInt or int len: the number of bytes to remove
        """

    @typing.overload
    def removeValue(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register):
        """
        
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register
        
        .. seealso::
        
            | :obj:`.removeValue(long, Register)`
        """

    @typing.overload
    def removeValue(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register):
        """
        Remove a value from the given time and register
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space.
         
         
        
        **IMPORANT:** The trace database cannot track the state (:obj:`TraceMemoryState.KNOWN`,
        etc.) with per-bit accuracy. It only has byte precision. If the given register specifies,
        e.g., only a single bit, then the entire byte will become marked
        :obj:`TraceMemoryState.UNKNOWN`, even though the remaining 7 bits could technically be
        known.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register
        """

    @typing.overload
    def setState(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, state: TraceMemoryState):
        """
        Set the state of memory over a given time and address range
         
         
        
        Setting state to :obj:`TraceMemoryState.KNOWN` via this method is not recommended. Setting
        bytes will automatically update the state accordingly.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.AddressRange range: the range
        :param TraceMemoryState state: the state
        """

    @typing.overload
    def setState(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, state: TraceMemoryState):
        """
        
        
        
        .. seealso::
        
            | :obj:`.setState(long, AddressRange, TraceMemoryState)`
        """

    @typing.overload
    def setState(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, state: TraceMemoryState):
        """
        
        
        
        .. seealso::
        
            | :obj:`.setState(long, AddressRange, TraceMemoryState)`
        """

    @typing.overload
    def setState(self, snap: typing.Union[jpype.JLong, int], set: ghidra.program.model.address.AddressSetView, state: TraceMemoryState):
        """
        Set the state of memory over a given time and address set
        
        
        .. seealso::
        
            | :obj:`.setState(long, AddressRange, TraceMemoryState)`
        """

    @typing.overload
    def setState(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, state: TraceMemoryState):
        """
        Set the state of a given register at a given time
         
         
        
        Setting state to :obj:`TraceMemoryState.KNOWN` via this method is not recommended. Setting
        bytes will automatically update the state accordingly.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :param TraceMemoryState state: the state
        """

    @typing.overload
    def setState(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, state: TraceMemoryState):
        """
        Set the state of a given register at a given time
         
         
        
        Setting state to :obj:`TraceMemoryState.KNOWN` via this method is not recommended. Setting
        bytes will automatically update the state accordingly.
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.lang.Register register: the register
        :param TraceMemoryState state: the state
        """

    @typing.overload
    def setValue(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], value: ghidra.program.model.lang.RegisterValue) -> int:
        """
        
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.RegisterValue value: the register value
        :return: the number of bytes written
        :rtype: int
        
        .. seealso::
        
            | :obj:`.setValue(long, RegisterValue)`
        """

    @typing.overload
    def setValue(self, snap: typing.Union[jpype.JLong, int], value: ghidra.program.model.lang.RegisterValue) -> int:
        """
        Set the value of a register at the given snap
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space. In those
        cases, the assignment affects all threads.
         
         
        
        **IMPORTANT:** The trace database cannot track the state (:obj:`TraceMemoryState.KNOWN`,
        etc.) with per-bit accuracy. It only has byte precision. If the given value specifies, e.g.,
        only a single bit, then the entire byte will become marked :obj:`TraceMemoryState.KNOWN`,
        even though the remaining 7 bits could technically be unknown.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.RegisterValue value: the register value
        :return: the number of bytes written
        :rtype: int
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def mostRecentStates(self) -> java.lang.Iterable[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        ...

    @property
    def blockSize(self) -> jpype.JInt:
        ...


class TraceRegisterContainer(ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A container of registers.
     
     
    
    NOTE: This is a special case of "container", since it need not be the immediate parent of the
    :obj:`TraceRegister`s it contains. Thus, this cannot be supplanted by
    :meth:`TraceObjectSchema.searchForCanonicalContainer(Class) <TraceObjectSchema.searchForCanonicalContainer>`.
    
    
    .. seealso::
    
        | :obj:`TraceRegister`
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceMemoryFlag(java.lang.Enum[TraceMemoryFlag]):

    class_: typing.ClassVar[java.lang.Class]
    EXECUTE: typing.Final[TraceMemoryFlag]
    WRITE: typing.Final[TraceMemoryFlag]
    READ: typing.Final[TraceMemoryFlag]
    VOLATILE: typing.Final[TraceMemoryFlag]

    @staticmethod
    @typing.overload
    def fromBits(flags: java.util.EnumSet[TraceMemoryFlag], mask: typing.Union[jpype.JInt, int]) -> java.util.EnumSet[TraceMemoryFlag]:
        ...

    @staticmethod
    @typing.overload
    def fromBits(mask: typing.Union[jpype.JInt, int]) -> java.util.Collection[TraceMemoryFlag]:
        ...

    def getBits(self) -> int:
        ...

    @staticmethod
    def toBits(flags: collections.abc.Sequence) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceMemoryFlag:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceMemoryFlag]:
        ...

    @property
    def bits(self) -> jpype.JByte:
        ...


class TraceMemory(ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    The memory model of a target object
     
     
    
    The convention for modeling valid addresses is to have children supporting
    :obj:`TraceMemoryRegion`. If no such children exist, then the client should assume no address is
    valid. Thus, for the client to confidently access any memory, at least one child region must
    exist. It may present the memory's entire address space in a single region.
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceOverlappedRegionException(ghidra.util.exception.UsrException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, conflicts: collections.abc.Sequence):
        ...

    def getConflicts(self) -> java.util.Collection[TraceMemoryRegion]:
        ...

    @property
    def conflicts(self) -> java.util.Collection[TraceMemoryRegion]:
        ...


class TraceMemorySpaceInputStream(java.io.InputStream):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.trace.model.program.TraceProgramView, space: TraceMemorySpace, range: ghidra.program.model.address.AddressRange):
        ...


class TraceMemoryRegion(ghidra.trace.model.TraceUniqueObject, ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A region of mapped target memory in a trace
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_RANGE: typing.Final = "_range"
    KEY_READABLE: typing.Final = "_readable"
    KEY_WRITABLE: typing.Final = "_writable"
    KEY_EXECUTABLE: typing.Final = "_executable"
    KEY_VOLATILE: typing.Final = "_volatile"

    @typing.overload
    def addFlags(self, lifespan: ghidra.trace.model.Lifespan, flags: collections.abc.Sequence):
        """
        Add the given flags, e.g., permissions, to this region
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param collections.abc.Sequence flags: the flags
        """

    @typing.overload
    def addFlags(self, snap: typing.Union[jpype.JLong, int], flags: collections.abc.Sequence):
        """
        Add the given flags, e.g., permissions, to this region
        
        :param jpype.JLong or int snap: the snap
        :param collections.abc.Sequence flags: the flags
        """

    @typing.overload
    def addFlags(self, snap: typing.Union[jpype.JLong, int], *flags: TraceMemoryFlag):
        """
        Add the given flags, e.g., permissions, to this region
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JArray[TraceMemoryFlag] flags: the flags
        """

    @typing.overload
    def clearFlags(self, lifespan: ghidra.trace.model.Lifespan, flags: collections.abc.Sequence):
        """
        Remove the given flags, e.g., permissions, from this region
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param collections.abc.Sequence flags: the flags
        """

    @typing.overload
    def clearFlags(self, snap: typing.Union[jpype.JLong, int], flags: collections.abc.Sequence):
        """
        Remove the given flags, e.g., permissions, from this region
        
        :param jpype.JLong or int snap: the snap
        :param collections.abc.Sequence flags: the flags
        """

    @typing.overload
    def clearFlags(self, snap: typing.Union[jpype.JLong, int], *flags: TraceMemoryFlag):
        """
        Remove the given flags, e.g., permissions, from this region
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JArray[TraceMemoryFlag] flags: the flags
        """

    def delete(self):
        """
        Delete this region from the trace
        """

    def getFlags(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Set[TraceMemoryFlag]:
        """
        Get the flags, e.g., permissions, of this region
        
        :param jpype.JLong or int snap: the snap
        :return: the flags
        :rtype: java.util.Set[TraceMemoryFlag]
        """

    def getLength(self, snap: typing.Union[jpype.JLong, int]) -> int:
        """
        Measure the length, in bytes, of this region's address range
        
        :param jpype.JLong or int snap: the snap
        :return: the length
        :rtype: int
        """

    def getMaxAddress(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the maximum address of the range
        
        :param jpype.JLong or int snap: the snap
        :return: the maximum address
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.getRange(long)`
        """

    def getMinAddress(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the minimum address of the range
        
        :param jpype.JLong or int snap: the snap
        :return: the minimum address
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.getRange(long)`
        """

    def getName(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the "short name" of this region
         
         
        
        This defaults to the "full name," but can be modified via :meth:`setName(long, String) <.setName>`
        
        :param jpype.JLong or int snap: the snap
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Get the "full name" of this region
         
         
        
        This is a unique key (within any snap) for retrieving the region, and may not be suitable for
        display on the screen.
        
        :return: the path
        :rtype: str
        """

    def getRange(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
        """
        Get the virtual memory address range of this region
        
        :param jpype.JLong or int snap: the snap
        :return: the address range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this region
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isExecute(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the :obj:`TraceMemoryFlag.EXECUTE` flag is present
        
        :param jpype.JLong or int snap: the snap
        :return: true if present, false if absent
        :rtype: bool
        """

    def isRead(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the :obj:`TraceMemoryFlag.READ` flag is present
        
        :param jpype.JLong or int snap: the snap
        :return: true if present, false if absent
        :rtype: bool
        """

    def isValid(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the region is valid at the given snapshot
         
         
        
        In object mode, a region's life may be disjoint, so checking if the snap occurs between
        creation and destruction is not quite sufficient. This method encapsulates validity. In
        object mode, it checks that the region object has a canonical parent at the given snapshot.
        In table mode, it checks that the lifespan contains the snap.
        
        :param jpype.JLong or int snap: the snapshot key
        :return: true if valid, false if not
        :rtype: bool
        """

    def isVolatile(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the :obj:`TraceMemoryFlag.VOLATILE` flag is present
        
        :param jpype.JLong or int snap: the snap
        :return: true if present, false if absent
        :rtype: bool
        """

    def isWrite(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the :obj:`TraceMemoryFlag.WRITE` flag is present
        
        :param jpype.JLong or int snap: the snap
        :return: true if present, false if absent
        :rtype: bool
        """

    def remove(self, snap: typing.Union[jpype.JLong, int]):
        """
        Remove this region from the given snap on
        
        :param jpype.JLong or int snap:
        """

    def setExecute(self, snap: typing.Union[jpype.JLong, int], execute: typing.Union[jpype.JBoolean, bool]):
        """
        Add or clear the :obj:`TraceMemoryFlag.EXECUTE` flag
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool execute: true to add, false to clear
        """

    @typing.overload
    def setFlags(self, lifespan: ghidra.trace.model.Lifespan, flags: collections.abc.Sequence):
        """
        Set the flags, e.g., permissions, of this region
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param collections.abc.Sequence flags: the flags
        """

    @typing.overload
    def setFlags(self, snap: typing.Union[jpype.JLong, int], flags: collections.abc.Sequence):
        """
        Set the flags, e.g., permissions, of this region
        
        :param jpype.JLong or int snap: the snap
        :param collections.abc.Sequence flags: the flags
        """

    @typing.overload
    def setFlags(self, snap: typing.Union[jpype.JLong, int], *flags: TraceMemoryFlag):
        """
        Set the flags, e.g., permissions, of this region
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JArray[TraceMemoryFlag] flags: the flags
        """

    def setLength(self, snap: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int]):
        """
        Set the length, in bytes, of this region's address range
         
         
        
        This adjusts the max address of the range so that its length becomes that given. Note that
        this sets the range from the given snap on to the same range, no matter what changes may have
        occurred since.
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JLong or int length: the desired length of the range
        :raises AddressOverflowException: if extending the range would cause the max address to
                    overflow
        :raises TraceOverlappedRegionException: if extending the region would cause it to overlap
                    another
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    def setMaxAddress(self, snap: typing.Union[jpype.JLong, int], max: ghidra.program.model.address.Address):
        """
        Set the maximum address of the range
         
         
        
        Note that this sets the range from the given snap on to the same range, no matter what
        changes may have occurred since.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address max: the new minimum
        :raises TraceOverlappedRegionException: if extending the region would cause it to overlap
                    another
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    def setMinAddress(self, snap: typing.Union[jpype.JLong, int], min: ghidra.program.model.address.Address):
        """
        Set the minimum address of the range
         
         
        
        Note that this sets the range from the given snap on to the same range, no matter what
        changes may have occurred since.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.Address min: the new minimum
        :raises TraceOverlappedRegionException: if extending the region would cause it to overlap
                    another
        
        .. seealso::
        
            | :obj:`.setRange(long, AddressRange)`
        """

    @typing.overload
    def setName(self, lifespan: ghidra.trace.model.Lifespan, name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this region
         
         
        
        The given name should be suitable for display on the screen.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str name: the name
        """

    @typing.overload
    def setName(self, snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this region
         
         
        
        The given name should be suitable for display on the screen.
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str name: the name
        """

    @typing.overload
    def setRange(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        """
        Set the virtual memory address range of this region
         
         
        
        The addresses in the range should be those the target's CPU would use to access the region,
        i.e., the virtual memory address if an MMU is involved, or the physical address if no MMU is
        involved.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param ghidra.program.model.address.AddressRange range: the address range
        """

    @typing.overload
    def setRange(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange):
        """
        Set the virtual memory address range of this region
         
         
        
        The addresses in the range should be those the target's CPU would use to access the region,
        i.e., the virtual memory address if an MMU is involved, or the physical address if no MMU is
        involved.
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.address.AddressRange range: the address range
        :raises TraceOverlappedRegionException: if the specified range would cause this region to
                    overlap another
        """

    def setRead(self, snap: typing.Union[jpype.JLong, int], read: typing.Union[jpype.JBoolean, bool]):
        """
        Add or clear the :obj:`TraceMemoryFlag.READ` flag
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool read: true to add, false to clear
        """

    def setVolatile(self, snap: typing.Union[jpype.JLong, int], vol: typing.Union[jpype.JBoolean, bool]):
        """
        Add or clear the :obj:`TraceMemoryFlag.VOLATILE` flag
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool vol: true to add, false to clear
        """

    def setWrite(self, snap: typing.Union[jpype.JLong, int], write: typing.Union[jpype.JBoolean, bool]):
        """
        Add or clear the :obj:`TraceMemoryFlag.WRITE` flag
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool write: true to add, false to clear
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def flags(self) -> java.util.Set[TraceMemoryFlag]:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def execute(self) -> jpype.JBoolean:
        ...


class RegisterValueConverter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, registerValue: ghidra.trace.model.target.TraceObjectValue):
        ...

    @staticmethod
    def convertValueToBigInteger(val: java.lang.Object) -> java.math.BigInteger:
        ...

    def getBytes(self, isBigEndian: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        ...

    def getBytesBigEndian(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getBytesLittleEndian(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getValue(self) -> java.math.BigInteger:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def bytesLittleEndian(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def bytesBigEndian(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...


class TraceMemoryManager(TraceMemoryOperations):
    """
    A store of memory observations over time in a trace
     
     
    
    The manager is not bound to any particular address space and may be used to access information
    about any memory address. For register spaces, you must use
    :meth:`getMemoryRegisterSpace(TraceThread, int, boolean) <.getMemoryRegisterSpace>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addRegion(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, flags: collections.abc.Sequence) -> TraceMemoryRegion:
        """
        Add a new region with the given properties
         
         
        
        Regions model the memory mappings of a debugging target. As such, they are never allowed to
        overlap. Additionally, to ensure :meth:`getLiveRegionByPath(long, String) <.getLiveRegionByPath>` returns a unique
        region, duplicate paths cannot exist in the same snap.
         
         
        
        Regions have a "full name" (path) as well as a short name. The path is immutable and can be
        used to reliably retrieve the same region later. The short name should be something suitable
        for display on the screen. Short names are mutable and can be -- but probbaly shouldn't be --
        duplicated.
        
        :param java.lang.String or str path: the "full name" of the region
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the region
        :param ghidra.program.model.address.AddressRange range: the address range of the region
        :param collections.abc.Sequence flags: the flags, e.g., permissions, of the region
        :return: the newly-added region
        :rtype: TraceMemoryRegion
        :raises TraceOverlappedRegionException: if the specified region would overlap an existing one
        """

    @typing.overload
    def addRegion(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, *flags: TraceMemoryFlag) -> TraceMemoryRegion:
        """
        
        
        
        .. seealso::
        
            | :obj:`.addRegion(String, Lifespan, AddressRange, Collection)`
        """

    def createOverlayAddressSpace(self, name: typing.Union[java.lang.String, str], base: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.AddressSpace:
        """
        Create a new address space with the given name based upon the given space
         
         
        
        The purpose of overlay spaces in traces is often to store bytes for things other than memory
        or registers. Some targets may expose other byte-based storage, or provide alternative views
        of memory.
         
         
        
        NOTE: This also provides a transitional piece for recording a model (sub)tree directly into a
        trace, without mapping to a Ghidra language first. As we experiment with that mode, we will
        likely instantiate traces with the "DATA:BE:64:default" language and generate an overlay
        space named after the path of each memory being recorded. Of course, the mapping still needs
        to occur between the trace and parts of the display and during emulation.
         
         
        
        NOTE: We are also moving away from (space, thread, frame) triples to uniquely identify
        register storage. Instead, that will be encoded into the address space itself. Register
        overlays will overlay register space and be named after the register container object, which
        subsumes thread and frame when applicable.
        
        :param java.lang.String or str name: the name of the new address space
        :param ghidra.program.model.address.AddressSpace base: the space after which this is modeled
        :return: the create space
        :rtype: ghidra.program.model.address.AddressSpace
        :raises DuplicateNameException: if an address space with the name already exists
        """

    @typing.overload
    def createRegion(self, path: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, flags: collections.abc.Sequence) -> TraceMemoryRegion:
        """
        Add a region created at the given snap, with no specified destruction snap
        
        
        .. seealso::
        
            | :obj:`.addRegion(String, Lifespan, AddressRange, Collection)`
        """

    @typing.overload
    def createRegion(self, path: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, *flags: TraceMemoryFlag) -> TraceMemoryRegion:
        """
        
        
        
        .. seealso::
        
            | :obj:`.createRegion(String, long, AddressRange, Collection)`
        """

    def deleteOverlayAddressSpace(self, name: typing.Union[java.lang.String, str]):
        """
        Delete an overlay address space
         
         
        
        TODO: At the moment, this will not destroy manager spaces created for the deleted address
        space. We should assess this behavior, esp. wrt. re-creating the address space later, and
        decide whether or not to clean up.
        
        :param java.lang.String or str name: the name of the address space to delete
        """

    def getAllRegions(self) -> java.util.Collection[TraceMemoryRegion]:
        """
        Get all the regions in this space or manager
        
        :return: the collection of all regions
        :rtype: java.util.Collection[TraceMemoryRegion]
        """

    def getLiveRegionByPath(self, snap: typing.Union[jpype.JLong, int], path: typing.Union[java.lang.String, str]) -> TraceMemoryRegion:
        """
        Get the region with the given path at the given snap
        
        :param jpype.JLong or int snap: the snap which must be within the region's lifespan
        :param java.lang.String or str path: the "full name" of the region
        :return: the region, or ``null`` if no region matches
        :rtype: TraceMemoryRegion
        """

    @typing.overload
    def getMemoryRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceMemorySpace:
        """
        Obtain a "memory" space bound to the register address space for a given thread and stack
        frame
        
        :param ghidra.trace.model.thread.TraceThread thread: the given thread
        :param jpype.JInt or int frame: the "level" of the given stack frame. 0 is the innermost frame.
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, or ``null`` if absent and not created
        :rtype: TraceMemorySpace
        """

    @typing.overload
    def getMemoryRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceMemorySpace:
        """
        Obtain a "memory" space bound to the register address space for frame 0 of a given thread
        
        :param ghidra.trace.model.thread.TraceThread thread: the given thread
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, or ``null`` if absent and not created
        :rtype: TraceMemorySpace
        
        .. seealso::
        
            | :obj:`.getMemoryRegisterSpace(TraceThread, int, boolean)`
        """

    @typing.overload
    def getMemoryRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceMemorySpace:
        """
        Obtain a "memory" space bound to the register address space for a stack frame
         
         
        
        Note this is simply a convenience, and does not in any way bind the space to the lifespan of
        the given frame. Nor, if the frame is moved, will this space move with it.
        
        :param ghidra.trace.model.stack.TraceStackFrame frame: the stack frame
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, or ``null`` if absent and not created
        :rtype: TraceMemorySpace
        
        .. seealso::
        
            | :obj:`.getMemoryRegisterSpace(TraceThread, int, boolean)`
        """

    def getMemorySpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceMemorySpace:
        """
        Obtain a memory space bound to a particular address space
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, or ``null`` if absent and not created
        :rtype: TraceMemorySpace
        """

    def getOrCreateOverlayAddressSpace(self, name: typing.Union[java.lang.String, str], base: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.AddressSpace:
        """
        Get or create an overlay address space
         
         
        
        If the space already exists, and it overlays the given base, the existing space is returned.
        If it overlays a different space, null is returned. If the space does not exist, it is
        created with the given base space.
        
        :param java.lang.String or str name: the name of the address space
        :param ghidra.program.model.address.AddressSpace base: the expected base space
        :return: the space, or null
        :rtype: ghidra.program.model.address.AddressSpace
        
        .. seealso::
        
            | :obj:`.createOverlayAddressSpace(String, AddressSpace)`
        """

    def getRegionContaining(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> TraceMemoryRegion:
        """
        Get the region at the given address and snap
        
        :param jpype.JLong or int snap: the snap which must be within the region's lifespan
        :param ghidra.program.model.address.Address address: the address which must be within the region's range
        :return: the region, or ``null`` if no region matches
        :rtype: TraceMemoryRegion
        """

    def getRegionsAddressSet(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        Get the addresses contained by regions at the given snap
         
         
        
        The implementation may provide a view that updates with changes.
        
        :param jpype.JLong or int snap: the snap which must be within the regions' lifespans
        :return: the union of ranges of matching regions
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getRegionsAddressSetWith(self, snap: typing.Union[jpype.JLong, int], predicate: java.util.function.Predicate[TraceMemoryRegion]) -> ghidra.program.model.address.AddressSetView:
        """
        Get the addresses contained by regions at the given snap satisfying the given predicate
         
         
        
        The implementation may provide a view that updates with changes.
        
        :param jpype.JLong or int snap: the snap which must be within the region's lifespans
        :param java.util.function.Predicate[TraceMemoryRegion] predicate: a predicate on regions to search for
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getRegionsAtSnap(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceMemoryRegion]:
        """
        Collect regions at the given snap
        
        :param jpype.JLong or int snap: the snap which must be within the regions' lifespans
        :return: the collection of matching regions
        :rtype: java.util.Collection[TraceMemoryRegion]
        """

    def getRegionsIntersecting(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceMemoryRegion]:
        """
        Collect regions intersecting the given lifespan and range
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan
        :param ghidra.program.model.address.AddressRange range: the range
        :return: the collection of matching regions
        :rtype: java.util.Collection[TraceMemoryRegion]
        """

    def getStateChanges(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]:
        """
        Collect all the state changes between two given snaps
        
        :param jpype.JLong or int from: the earlier snap
        :param jpype.JLong or int to: the later snap
        :return: the collection of state changes
        :rtype: java.util.Collection[java.util.Map.Entry[ghidra.trace.model.TraceAddressSnapRange, TraceMemoryState]]
        """

    @property
    def allRegions(self) -> java.util.Collection[TraceMemoryRegion]:
        ...

    @property
    def regionsAtSnap(self) -> java.util.Collection[TraceMemoryRegion]:
        ...

    @property
    def regionsAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...



__all__ = ["TraceRegister", "TraceMemorySpace", "RegisterValueException", "TraceMemoryState", "TraceMemoryOperations", "TraceRegisterContainer", "TraceMemoryFlag", "TraceMemory", "TraceOverlappedRegionException", "TraceMemorySpaceInputStream", "TraceMemoryRegion", "RegisterValueConverter", "TraceMemoryManager"]
