from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.stack
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang # type: ignore
import java.nio # type: ignore


T = typing.TypeVar("T")
U = typing.TypeVar("U")


class TraceCodeUnitsView(TraceBaseCodeUnitsView[TraceCodeUnit]):
    """
    A view of all code units
     
     
    
    In particular, this includes default / undefined units. If an address is valid, this view will
    show there is a code unit containing it.
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceBaseCodeUnitsView(java.lang.Object, typing.Generic[T]):
    """
    A view of code units stored in a trace, possibly restricted to a particular subset by type,
    address space, or thread and frame.
    """

    class_: typing.ClassVar[java.lang.Class]

    def containsAddress(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> bool:
        """
        Check if the given address is contained by a live unit
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the address to check
        :return: true if it is contained, false if not
        :rtype: bool
        """

    @typing.overload
    def coversRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        Check if the given span of snaps and range of addresses is covered by the units
         
         
        
        This checks if every (snap, address) point within the given box is contained within some code
        unit in this view.
        
        :param ghidra.trace.model.Lifespan span: the span of snaps
        :param ghidra.program.model.address.AddressRange range: the address range
        :return: true if covered, false otherwise
        :rtype: bool
        """

    @typing.overload
    def coversRange(self, range: ghidra.trace.model.TraceAddressSnapRange) -> bool:
        """
        Check if the given address-snap range is covered by the units
         
         
        
        This checks if every (snap, address) point within the given box is contained within some code
        unit in this view.
        
        :param ghidra.trace.model.TraceAddressSnapRange range: the address-snap range
        :return: true if covered, false otherwise
        :rtype: bool
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get the live units whose start addresses are within the specified range
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param ghidra.program.model.address.Address min: the minimum start address, inclusive
        :param ghidra.program.model.address.Address max: the maximum start address, inclusive
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get the live units whose start addresses are in the given set
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param ghidra.program.model.address.AddressSetView set: the address set
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get the live units whose start addresses are within the specified range
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param ghidra.program.model.address.AddressRange range: the address range
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get the live units whose start addresses are within the specified range
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param ghidra.program.model.address.Address start: the minimum (forward) or maximum (backward) start address, inclusive
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get all the live units
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def get(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get the live units whose start addresses are within the given register
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def get(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register, forward: typing.Union[jpype.JBoolean, bool]) -> java.lang.Iterable[T]:
        """
        Get the live units whose start addresses are within the given register
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param ghidra.program.model.lang.Register register: the register
        :param jpype.JBoolean or bool forward: true to order the units by increasing address, false for descending
        :return: the iterable of units
        :rtype: java.lang.Iterable[T]
        """

    @typing.overload
    def getAddressSetView(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        Get all addresses contained by live units at the given snap
         
         
        
        Note that the ranges in this set may not be coalesced. If a coalesced set is required, wrap
        it with :obj:`UnionAddressSetView`.
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :return: a (lazy) view of the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def getAddressSetView(self, snap: typing.Union[jpype.JLong, int], within: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressSetView:
        """
        Get all addresses contained by live units at the given snap, within a restricted range
         
         
        
        Note that the ranges in this set may not be coalesced. If a coalesced set is required, wrap
        it with :obj:`UnionAddressSetView`. The returned ranges are not necessarily enclosed by
        ``within``, but they will intersect it. If strict enclosure is required, wrap the set
        with :obj:`IntersectionAddressSetView`.
        
        :param jpype.JLong or int snap: the snap during which the units must be alive
        :param ghidra.program.model.address.AddressRange within: the range to restrict the view
        :return: a (lazy) view of the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getAfter(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the nearest live unit whose start address is after the given address
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the address which the unit's start must follow
        :return: the code unit, or ``null`` if it doesn't exist
        :rtype: T
        """

    def getAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the unit starting at exactly this address
         
        Note that the unit need only contain the given snap
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the unit's start address
        :return: the code unit, or ``null`` if it doesn't exist
        :rtype: T
        """

    def getBefore(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the nearest live unit whose start address is before the given address
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the address which the unit's start must precede
        :return: the code unit, or ``null`` if it doesn't exist
        :rtype: T
        """

    def getCeiling(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the nearest live unit whose start address is at or after the given address
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the address which the unit's start must equal or follow
        :return: the code unit, or ``null`` if it doesn't exist
        :rtype: T
        """

    @typing.overload
    def getContaining(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the live unit containing the given address
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the address which the unit must contain
        :return: the code unit, or ``null`` if it doesn't exist
        :rtype: T
        """

    @typing.overload
    def getContaining(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> T:
        """
        Get the unit which completely contains the given register
         
         
        
        This does not descend into structures.
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.lang.Register register: the register
        :return: the unit or ``unit``
        :rtype: T
        """

    @typing.overload
    def getContaining(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> T:
        """
        Get the unit which completely contains the given register
         
         
        
        This does not descend into structures.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.lang.Register register: the register
        :return: the unit or ``unit``
        :rtype: T
        """

    def getFloor(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> T:
        """
        Get the nearest live unit whose start address is at or before the given address
        
        :param jpype.JLong or int snap: the snap during which the unit must be alive
        :param ghidra.program.model.address.Address address: the address which the unit's start must equal or precede
        :return: the code unit, or ``null`` if it doesn't exist
        :rtype: T
        """

    @typing.overload
    def getForRegister(self, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> T:
        """
        Get the unit (or component of a structure) which spans exactly the addresses of the given
        register
        
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register
        :return: the unit or ``null``
        :rtype: T
        """

    @typing.overload
    def getForRegister(self, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], register: ghidra.program.model.lang.Register) -> T:
        """
        Get the unit (or component of a structure) which spans exactly the addresses of the given
        platform register
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param jpype.JLong or int snap: the snap
        :param ghidra.program.model.lang.Register register: the register
        :return: the unit or ``null``
        :rtype: T
        """

    def getIntersecting(self, tasr: ghidra.trace.model.TraceAddressSnapRange) -> java.lang.Iterable[T]:
        """
        Get the units which intersect the given box, in no particular order
        
        :param ghidra.trace.model.TraceAddressSnapRange tasr: the box (snap range by address range)
        :return: an iterable over the intersecting units
        :rtype: java.lang.Iterable[T]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace for this view
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    @typing.overload
    def intersectsRange(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> bool:
        """
        Check if the given span of snaps and range of addresses intersects any unit
         
         
        
        This checks if any (snap, address) point within the given box is contained within some code
        unit in this view.
        
        :param ghidra.trace.model.Lifespan span: the span of snaps
        :param ghidra.program.model.address.AddressRange range: the address range
        :return: true if intersecting, false otherwise
        :rtype: bool
        """

    @typing.overload
    def intersectsRange(self, range: ghidra.trace.model.TraceAddressSnapRange) -> bool:
        """
        Check if the given span of snaps and range of addresses intersects any unit
         
         
        
        This checks if any (snap, address) point within the given box is contained within some code
        unit in this view.
        
        :param ghidra.trace.model.TraceAddressSnapRange range: the address-snap range
        :return: true if intersecting, false otherwise
        :rtype: bool
        """

    def size(self) -> int:
        """
        Get the total number of *defined* units in this view
        
        :return: the size
        :rtype: int
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def intersecting(self) -> java.lang.Iterable[T]:
        ...

    @property
    def addressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...


class TraceDataView(TraceBaseCodeUnitsView[TraceData]):
    """
    A view of all data units
    
     
    
    This only excludes instructions. In particular, it includes default / undefined data units.
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceBaseDefinedUnitsView(TraceBaseCodeUnitsView[T], typing.Generic[T]):
    """
    A :obj:`TraceBaseCodeUnitsView` restricted (at least) to defined units
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def clear(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, clearContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Clear the units contained within the given span and address range.
         
         
        
        Any units alive before the given span are truncated instead of deleted. That is, their end
        snaps are reduced such that they no longer intersect the given span. Note that the same is
        not true of a unit's start snap. If the start snap is contained in the span, the unit is
        deleted, even if its end snap is outside the span.
        
        :param ghidra.trace.model.Lifespan span: the span to clear
        :param ghidra.program.model.address.AddressRange range: the range to clear
        :param jpype.JBoolean or bool clearContext: true to clear the register context as well
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
        :raises CancelledException: if the clear is cancelled
        """

    @typing.overload
    def clear(self, span: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, monitor: ghidra.util.task.TaskMonitor):
        """
        Clear the units contained within the given span and register
         
         
        
        Any units alive before the given span are truncated instead of deleted.
        
        :param ghidra.trace.model.Lifespan span: the span to clear
        :param ghidra.program.model.lang.Register register: the register
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
        :raises CancelledException: if the clear is cancelled
        """

    @typing.overload
    def clear(self, platform: ghidra.trace.model.guest.TracePlatform, span: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, monitor: ghidra.util.task.TaskMonitor):
        """
        Clear the units contained within the given span and platform register
         
         
        
        Any units alive before the given span are truncated instead of deleted.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param ghidra.trace.model.Lifespan span: the span to clear
        :param ghidra.program.model.lang.Register register: the register
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
        :raises CancelledException: if the clear is cancelled
        """


class TraceDefinedDataView(TraceBaseDefinedUnitsView[TraceData]):
    """
    A view of defined data units
    
     
    
    This view excludes instructions and default / undefined data units.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]) -> TraceData:
        """
        Create a data unit starting at the given address
         
         
        
        If the given type is already part of this trace, its platform is used as is. If not, then it
        is resolved to the host platform.
        
        :param ghidra.trace.model.Lifespan lifespan: the span for which the unit is effective
        :param ghidra.program.model.address.Address address: the starting address
        :param ghidra.program.model.data.DataType dataType: the data type for the unit
        :param jpype.JInt or int length: the length of the unit, -1 for unspecified
        :return: the new data unit
        :rtype: TraceData
        :raises CodeUnitInsertionException: if there's a conflict
        """

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, platform: ghidra.trace.model.guest.TracePlatform, dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]) -> TraceData:
        """
        Create a data unit starting at the given address
         
         
        
        The given type is resolved to the given platform, even if the type already exists in the
        trace by another platform.
        
        :param ghidra.trace.model.Lifespan lifespan: the span for which the unit is effective
        :param ghidra.program.model.address.Address address: the starting address
        :param ghidra.trace.model.guest.TracePlatform platform: the platform for the type's :obj:`DataOrganization`
        :param ghidra.program.model.data.DataType dataType: the data type for the unit
        :param jpype.JInt or int length: the length of the unit, -1 for unspecified
        :return: the new data unit
        :rtype: TraceData
        :raises CodeUnitInsertionException: if there's a conflict
        """

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType) -> TraceData:
        """
        Create a data unit of unspecified length starting at the given address
         
         
        
        The length will be determined by the data type, possibly by examining the bytes, e.g., a
        null-terminated UTF-8 string. If the given type is already part of this trace, its platform
        is used as is. If not, then it is resolved to the host platform.
        
        :param ghidra.trace.model.Lifespan lifespan: the span for which the unit is effective
        :param ghidra.program.model.address.Address address: the starting address
        :param ghidra.program.model.data.DataType dataType: the data type for the unit
        :return: the new data unit
        :rtype: TraceData
        :raises CodeUnitInsertionException: if there's a conflict
        """

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, platform: ghidra.trace.model.guest.TracePlatform, dataType: ghidra.program.model.data.DataType) -> TraceData:
        """
        Create a data unit of unspecified length starting at the given address
         
         
        
        The length will be determined by the data type, possibly by examining the bytes, e.g., a
        null-terminated UTF-8 string. The given type is resolved to the given platform, even if the
        type already exists in the trace by another platform.
        
        :param ghidra.trace.model.Lifespan lifespan: the span for which the unit is effective
        :param ghidra.program.model.address.Address address: the starting address
        :param ghidra.trace.model.guest.TracePlatform platform: the platform for the type's :obj:`DataOrganization`
        :param ghidra.program.model.data.DataType dataType: the data type for the unit
        :return: the new data unit
        :rtype: TraceData
        :raises CodeUnitInsertionException: if there's a conflict
        """

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, dataType: ghidra.program.model.data.DataType) -> TraceData:
        """
        Create a data unit on the given register
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space. In those
        cases, the assignment affects all threads. The type is resolved to the host platform, even if
        it already exists in the trace by another platform.
        
        :param ghidra.trace.model.Lifespan lifespan: the span for which the unit is effective
        :param ghidra.program.model.lang.Register register: the register to assign a data type
        :param ghidra.program.model.data.DataType dataType: the data type for the register
        :return: the new data unit
        :rtype: TraceData
        :raises CodeUnitInsertionException: if there's a conflict
        """

    @typing.overload
    def create(self, platform: ghidra.trace.model.guest.TracePlatform, lifespan: ghidra.trace.model.Lifespan, register: ghidra.program.model.lang.Register, dataType: ghidra.program.model.data.DataType) -> TraceData:
        """
        Create a data unit on the given platform register
         
         
        
        If the register is memory mapped, this will delegate to the appropriate space. In those
        cases, the assignment affects all threads. The type is resolved to the given platform, even
        if it already exists in the trace by another platform.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform whose language defines the register
        :param ghidra.trace.model.Lifespan lifespan: the span for which the unit is effective
        :param ghidra.program.model.lang.Register register: the register to assign a data type
        :param ghidra.program.model.data.DataType dataType: the data type for the register
        :return: the new data unit
        :rtype: TraceData
        :raises CodeUnitInsertionException: if there's a conflict
        """


class TraceInstruction(TraceCodeUnit, ghidra.program.model.listing.Instruction):
    """
    An instruction in a :obj:`Trace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getGuestDefaultFallThrough(self) -> ghidra.program.model.address.Address:
        """
        Get the default fall-through as viewed in the instruction's native address space
        
        :return: the default fall-through
        :rtype: ghidra.program.model.address.Address
        """

    def getGuestDefaultFlows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Get the default flows as viewed in the instruction's native address space
        
        :return: the default flows
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @property
    def guestDefaultFallThrough(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def guestDefaultFlows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...


class TraceCodeUnit(ghidra.program.model.listing.CodeUnit):
    """
    A code unit in a :obj:`Trace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this code unit
        """

    def getBounds(self) -> ghidra.trace.model.TraceAddressSnapRange:
        """
        Get the bounds of this unit in space and time
        
        :return: the bounds
        :rtype: ghidra.trace.model.TraceAddressSnapRange
        """

    def getBytes(self, buffer: java.nio.ByteBuffer, addressOffset: typing.Union[jpype.JInt, int]) -> int:
        """
        Read bytes starting at this unit's address plus the given offset into the given buffer
         
         
        
        This method honors the markers (position and limit) of the destination buffer. Use those
        markers to control the destination offset and maximum length.
        
        :param java.nio.ByteBuffer buffer: the destination buffer
        :param jpype.JInt or int addressOffset: the offset from this unit's (minimum) address
        :return: the number of bytes read
        :rtype: int
        """

    def getEndSnap(self) -> int:
        """
        Get the end snap of this code unit
        
        :return: the last snap of this unit's lifespan
        :rtype: int
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language of this code unit
         
         
        
        Currently, for data units, this is always the base or "host" language of the trace. For
        instructions, this may be a guest language.
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        """
        Get the lifespan of this code unit
        
        :return: the lifespan
        :rtype: ghidra.trace.model.Lifespan
        """

    def getPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        """
        Get the platform for this unit
        
        :return: the platform
        :rtype: ghidra.trace.model.guest.TracePlatform
        """

    def getProperty(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T]) -> T:
        """
        Get a property having the given type
         
         
        
        If the named property has a sub-type of the given ``valueClass``, the value (possibly
        ``null``) is returned. If the property does not exist, ``null`` is returned.
        Otherwise :obj:`TypeMismatchException` is thrown, even if the property is not set at this
        unit's address.
         
         
        
        Note that getting a :obj:`Void` property will always return ``null``. Use
        :meth:`getVoidProperty(String) <.getVoidProperty>` instead to detect if the property is set.
        :meth:`hasProperty(String) <.hasProperty>` will also work, but it does not verify that the property's type
        is actually :obj:`Void`.
        
        :param java.lang.String or str name: the name of the property
        :param java.lang.Class[T] valueClass: the expected type of the value (or a super-type thereof)
        :return: the value of the property, or ``null``
        :rtype: T
        """

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range covered by this unit
        
        :return: the range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getStartSnap(self) -> int:
        """
        Get the start snap of this code unit
        
        :return: the first snap of this unit's lifespan
        :rtype: int
        """

    def getThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the thread associated with this code unit
         
         
        
        A thread is associated with a code unit if it exists in a register space
        
        :return: the thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace in which this code unit exists
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def setEndSnap(self, endSnap: typing.Union[jpype.JLong, int]):
        """
        Set the end snap of this code unit
        
        :param jpype.JLong or int endSnap: the last snap of this unit's lifespan
        :raises IllegalArgumentException: if the end snap is less than the start snap
        """

    def setProperty(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[T], value: T):
        """
        Set a property of the given type to the given value
         
         
        
        This method is preferred to :meth:`setTypedProperty(String, Object) <.setTypedProperty>`, because in the case
        the property map does not already exist, the desired type is given explicitly.
         
         
        
        While it is best practice to match ``valueClass`` exactly with the type of the map, this
        method will work so long as the given ``valueClass`` is a subtype of the map's type. If
        the property map does not already exist, it is created with the given ``valueClass``.
        Note that there is no established mechanism for restoring values of a subtype from the
        underlying database.
         
         
        
        Currently, the only supported types are :obj:`Integer`, :obj:`String`, :obj:`Void`, and
        subtypes of :obj:`Saveable`.
        
        :param java.lang.String or str name: the name of the property
        :param java.lang.Class[T] valueClass: the type of the property
        :param T value: the value of the property
        """

    def setTypedProperty(self, name: typing.Union[java.lang.String, str], value: T):
        """
        Set a property having the same type as the given value
         
         
        
        If the named property has a super-type of the value's type, the value is accepted. If not, a
        :obj:`TypeMismatchException` is thrown. If the property map does not already exist, it is
        created having *exactly* the type of the given value.
         
         
        
        This method exists for two reasons: 1) To introduce the type variable U, which is more
        existential, and 2) to remove the requirement to subtype :obj:`Saveable`. Otherwise, this
        method is identical in operation to :meth:`setProperty(String, Saveable) <.setProperty>`.
        
        :param java.lang.String or str name: the name of the property
        :param T value: the value of the property
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def endSnap(self) -> jpype.JLong:
        ...

    @endSnap.setter
    def endSnap(self, value: jpype.JLong):
        ...

    @property
    def bounds(self) -> ghidra.trace.model.TraceAddressSnapRange:
        ...

    @property
    def startSnap(self) -> jpype.JLong:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def platform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...


class TraceCodeOperations(java.lang.Object):
    """
    This interface is the entry for operating on code units of a trace
     
     
    
    See :obj:`TraceCodeManager` for some examples. This interface does not directly support
    operating on the units. Rather it provides access to various "views" of the code units,
    supporting a fluent syntax for operating on the units. The views are various subsets of units by
    type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def codeUnits(self) -> TraceCodeUnitsView:
        """
        Get a view of all the code units in the listing
        
        :return: the code-units view
        :rtype: TraceCodeUnitsView
        """

    def data(self) -> TraceDataView:
        """
        Get a view of only the data units (defined and undefined) in the listing
        
        :return: the data-units view
        :rtype: TraceDataView
        """

    def definedData(self) -> TraceDefinedDataView:
        """
        Get a view of only the defined data units in the listing
         
         
        
        This view supports the creation of new data units. This view also supports clearing.
        
        :return: the defined-data-units view
        :rtype: TraceDefinedDataView
        """

    def definedUnits(self) -> TraceDefinedUnitsView:
        """
        Get a view of only the defined units (data and instructions) in the listing
         
         
        
        This view support clearing.
        
        :return: the defined-units-view
        :rtype: TraceDefinedUnitsView
        """

    def instructions(self) -> TraceInstructionsView:
        """
        Get a view of only the instructions in the listing
         
         
        
        This view supports the creation of new instruction units. This view also supports clearing.
        
        :return: the instruction-units view
        :rtype: TraceInstructionsView
        """

    def undefinedData(self) -> TraceUndefinedDataView:
        """
        Get a view of only the undefined data units in the listing
        
        :return: return the undefined-data-units view
        :rtype: TraceUndefinedDataView
        """


class TraceDefinedUnitsView(TraceBaseDefinedUnitsView[TraceCodeUnit]):
    """
    A view of defined units
    
     
    
    This view excludes default / undefined data units.
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceCodeSpace(TraceCodeOperations):
    """
    A space within a :obj:`CodeManager` bound to a specific address space or thread and frame
     
     
    
    Ordinarily, the manager can operate on all memory address spaces without the client needing to
    bind to it specifically. However, there may be occasions where it's convenient (and more
    efficient) to bind to the address space, anyway. Operating on register units requires binding to
    the space.
    
    
    .. seealso::
    
        | :obj:`TraceCodeManager.getCodeSpace(AddressSpace, boolean)`
    
        | :obj:`TraceCodeManager.getCodeRegisterSpace(TraceThread, int, boolean)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the address space of this code space
        
        :return: the address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class TraceUndefinedDataView(TraceBaseCodeUnitsView[TraceData]):
    """
    A view of default / undefined data units
    
     
    
    This excludes all instructions and defined data. Typically, it is used to find ranges of
    undefined addresses.
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceCodeManager(TraceCodeOperations):
    """
    The manager for trace code units, i.e., the equivalent of :obj:`Listing`
    
     
    
    This supports a "fluent" interface, which differs from :obj:`Listing`. For example, instead of
    :meth:`Listing.getInstructionContaining(Address) <Listing.getInstructionContaining>`, a client would invoke :meth:`instructions() <.instructions>`
    then :meth:`TraceInstructionsView.getContaining(long, Address) <TraceInstructionsView.getContaining>`. Because traces include register
    spaces, this chain could be preceded by :meth:`getCodeSpace(AddressSpace, boolean) <.getCodeSpace>` or
    :meth:`getCodeRegisterSpace(TraceThread, int, boolean) <.getCodeRegisterSpace>`.
     
     
    
    To create an instruction, see
    :meth:`TraceInstructionsView.create(Lifespan, Address, TracePlatform, InstructionPrototype, ProcessorContextView, int) <TraceInstructionsView.create>`.
    Since clients do not ordinarily have an :obj:`InstructionPrototype` in hand, the more common
    method is to invoke the :obj:`Disassembler` on :meth:`Trace.getProgramView() <Trace.getProgramView>`.
     
     
    
    To create a data unit, see :meth:`TraceDefinedDataView.create(Lifespan, Address, DataType, int) <TraceDefinedDataView.create>`.
    The method chain to create a data unit in memory is :meth:`definedData() <.definedData>` then
    ``create(...)``. The method chain to create a data unit on a register is
    :meth:`getCodeRegisterSpace(TraceThread, int, boolean) <.getCodeRegisterSpace>`, then
    :meth:`TraceCodeSpace.definedData() <TraceCodeSpace.definedData>`, then
    :meth:`TraceDefinedDataView.create(Lifespan, Register, DataType) <TraceDefinedDataView.create>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCodeAdded(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        Query for the address set where code units have been added between the two given snaps
        
        :param jpype.JLong or int from: the beginning snap
        :param jpype.JLong or int to: the ending snap
        :return: the view of addresses where units have been added
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def getCodeRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceCodeSpace:
        """
        Get the code space for registers of the given thread's innermost frame
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, of ``null`` if absent and not created
        :rtype: TraceCodeSpace
        """

    @typing.overload
    def getCodeRegisterSpace(self, thread: ghidra.trace.model.thread.TraceThread, frameLevel: typing.Union[jpype.JInt, int], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceCodeSpace:
        """
        Get the code space for registers of the given thread and frame
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JInt or int frameLevel: the frame (0 for innermost)
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, of ``null`` if absent and not created
        :rtype: TraceCodeSpace
        """

    @typing.overload
    def getCodeRegisterSpace(self, frame: ghidra.trace.model.stack.TraceStackFrame, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceCodeSpace:
        """
        Get the code space for registers of the given stack frame
         
         
        
        Note this is simply a shortcut for :meth:`getCodeRegisterSpace(TraceThread, int, boolean) <.getCodeRegisterSpace>`,
        and does not in any way bind the space to the lifetime of the given frame. Nor, if the frame
        is moved, will this space move with it.
        
        :param ghidra.trace.model.stack.TraceStackFrame frame: the frame whose space to get
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, or ``null`` if absent and not created
        :rtype: TraceCodeSpace
        """

    def getCodeRemoved(self, from_: typing.Union[jpype.JLong, int], to: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        Query for the address set where code units have been removed between the two given snaps
        
        :param jpype.JLong or int from: the beginning snap
        :param jpype.JLong or int to: the ending snap
        :return: the view of addresses where units have been removed
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getCodeSpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> TraceCodeSpace:
        """
        Get the code space for the memory of the given address space
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JBoolean or bool createIfAbsent: true to create the space if it's not already present
        :return: the space, of ``null`` if absent and not created
        :rtype: TraceCodeSpace
        """


class TraceData(TraceCodeUnit, ghidra.program.model.listing.Data):
    """
    A data unit in a :obj:`Trace`
    """

    class_: typing.ClassVar[java.lang.Class]


class TraceInstructionsView(TraceBaseDefinedUnitsView[TraceInstruction]):
    """
    A view of instruction units
    
     
    
    This view excludes all data units, defined or undefined
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addInstructionSet(self, lifespan: ghidra.trace.model.Lifespan, platform: ghidra.trace.model.guest.TracePlatform, instructionSet: ghidra.program.model.lang.InstructionSet, overwrite: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Create several instructions
         
         
        
        **NOTE:** This does not throw :obj:`CodeUnitInsertionException`. Conflicts are instead
        recorded in the ``instructionSet``.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan for all instruction units
        :param ghidra.trace.model.guest.TracePlatform platform: the optional guest platform, null for the host
        :param ghidra.program.model.lang.InstructionSet instructionSet: the set of instructions to add
        :param jpype.JBoolean or bool overwrite: true to replace conflicting instructions
        :return: the (host) address set of instructions actually added
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def addInstructionSet(self, lifespan: ghidra.trace.model.Lifespan, instructionSet: ghidra.program.model.lang.InstructionSet, overwrite: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Create several instructions for the host platform
         
         
        
        **NOTE:** This does not throw :obj:`CodeUnitInsertionException`. Conflicts are instead
        recorded in the ``instructionSet``.
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan for all instruction units
        :param ghidra.program.model.lang.InstructionSet instructionSet: the set of instructions to add
        :param jpype.JBoolean or bool overwrite: true to replace conflicting instructions
        :return: the (host) address set of instructions actually added
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, platform: ghidra.trace.model.guest.TracePlatform, prototype: ghidra.program.model.lang.InstructionPrototype, context: ghidra.program.model.lang.ProcessorContextView, forcedLengthOverride: typing.Union[jpype.JInt, int]) -> TraceInstruction:
        """
        Create an instruction
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan for the instruction unit
        :param ghidra.program.model.address.Address address: the starting address of the instruction
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :param ghidra.program.model.lang.InstructionPrototype prototype: the instruction prototype
        :param ghidra.program.model.lang.ProcessorContextView context: the input disassembly context for the instruction
        :param jpype.JInt or int forcedLengthOverride: reduced instruction byte-length (1..7) or 0 to use default length
        :return: the new instruction
        :rtype: TraceInstruction
        :raises CodeUnitInsertionException: if the instruction cannot be created
        """

    @typing.overload
    def create(self, lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, context: ghidra.program.model.lang.ProcessorContextView, forcedLengthOverride: typing.Union[jpype.JInt, int]) -> TraceInstruction:
        """
        Create an instruction for the host platform
        
        :param ghidra.trace.model.Lifespan lifespan: the lifespan for the instruction unit
        :param ghidra.program.model.address.Address address: the starting address of the instruction
        :param ghidra.program.model.lang.InstructionPrototype prototype: the instruction prototype
        :param ghidra.program.model.lang.ProcessorContextView context: the input disassembly context for the instruction
        :param jpype.JInt or int forcedLengthOverride: reduced instruction byte-length (1..7) or 0 to use default length
        :return: the new instruction
        :rtype: TraceInstruction
        :raises CodeUnitInsertionException: if the instruction cannot be created
        """



__all__ = ["TraceCodeUnitsView", "TraceBaseCodeUnitsView", "TraceDataView", "TraceBaseDefinedUnitsView", "TraceDefinedDataView", "TraceInstruction", "TraceCodeUnit", "TraceCodeOperations", "TraceDefinedUnitsView", "TraceCodeSpace", "TraceUndefinedDataView", "TraceCodeManager", "TraceData", "TraceInstructionsView"]
