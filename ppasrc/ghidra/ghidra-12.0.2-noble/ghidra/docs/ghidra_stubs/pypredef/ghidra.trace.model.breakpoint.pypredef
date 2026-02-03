from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.target.iface
import ghidra.trace.model.thread
import java.lang # type: ignore
import java.util # type: ignore
import org.apache.commons.collections4.set # type: ignore


class TraceBreakpointManager(java.lang.Object):
    """
    A store for recording breakpoint placement over time in a trace
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addBreakpoint(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange, threads: collections.abc.Sequence, kinds: collections.abc.Sequence, enabled: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]) -> TraceBreakpointLocation:
        """
        Add a breakpoint to the trace
        
        :param java.lang.String or str path: the "full name" of the breakpoint
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the breakpoint
        :param ghidra.program.model.address.AddressRange range: the address range of the breakpoint
        :param collections.abc.Sequence threads: an optional set of threads to which the breakpoint applies. Empty for every
                    thread, i.e, the process.
        :param collections.abc.Sequence kinds: the kinds of breakpoint
        :param jpype.JBoolean or bool enabled: true if the breakpoint is enabled
        :param java.lang.String or str comment: a user comment
        :return: the new breakpoint.
        :rtype: TraceBreakpointLocation
        :raises DuplicateNameException: if a breakpoint with the same path already exists within an
                    overlapping snap
        """

    @typing.overload
    def addBreakpoint(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan, address: ghidra.program.model.address.Address, threads: collections.abc.Sequence, kinds: collections.abc.Sequence, enabled: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]) -> TraceBreakpointLocation:
        """
        Add a breakpoint to the trace at a single address
        
        
        .. seealso::
        
            | :obj:`.addBreakpoint(String, Lifespan, AddressRange, Collection, Collection, boolean, String)`
        """

    def getAllBreakpointLocations(self) -> java.util.Collection[TraceBreakpointLocation]:
        """
        Collect all breakpoint locations in the trace
        
        :return: the locations
        :rtype: java.util.Collection[TraceBreakpointLocation]
        """

    def getAllBreakpointSpecifications(self) -> java.util.Collection[TraceBreakpointSpec]:
        """
        Collect all breakpoint specifications in the trace
        
        :return: the specifications
        :rtype: java.util.Collection[TraceBreakpointSpec]
        """

    def getBreakpointLocationsByPath(self, path: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceBreakpointLocation]:
        """
        Collect breakpoints locations having the given "full name"
        
        :param java.lang.String or str path: the path
        :return: the locations
        :rtype: java.util.Collection[TraceBreakpointLocation]
        """

    def getBreakpointSpecificationsByPath(self, path: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceBreakpointSpec]:
        """
        Collect breakpoints specifications having the given "full name"
        
        :param java.lang.String or str path: the path
        :return: the specifications
        :rtype: java.util.Collection[TraceBreakpointSpec]
        """

    def getBreakpointsAt(self, snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address) -> java.util.Collection[TraceBreakpointLocation]:
        """
        Collect breakpoints containing the given snap and address
        
        :param jpype.JLong or int snap: the time
        :param ghidra.program.model.address.Address address: the location
        :return: the collection of breakpoints
        :rtype: java.util.Collection[TraceBreakpointLocation]
        """

    def getBreakpointsIntersecting(self, span: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange) -> java.util.Collection[TraceBreakpointLocation]:
        """
        Collect breakpoints intersecting the given span and address range
        
        :param ghidra.trace.model.Lifespan span: the span
        :param ghidra.program.model.address.AddressRange range: the address range
        :return: the collection of breakpoints
        :rtype: java.util.Collection[TraceBreakpointLocation]
        """

    def getPlacedBreakpointByPath(self, snap: typing.Union[jpype.JLong, int], path: typing.Union[java.lang.String, str]) -> TraceBreakpointLocation:
        """
        Get the placed breakpoint at the given snap by the given path
        
        :param jpype.JLong or int snap: the snap which the breakpoint's lifespan must contain
        :param java.lang.String or str path: the path of the breakpoint
        :return: the breakpoint, or ``null`` if no breakpoint matches
        :rtype: TraceBreakpointLocation
        """

    @typing.overload
    def placeBreakpoint(self, path: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, threads: collections.abc.Sequence, kinds: collections.abc.Sequence, enabled: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]) -> TraceBreakpointLocation:
        """
        Add a breakpoint to the trace starting at a given snap
        
        
        .. seealso::
        
            | :obj:`.addBreakpoint(String, Lifespan, AddressRange, Collection, Collection, boolean, String)`
        """

    @typing.overload
    def placeBreakpoint(self, path: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int], address: ghidra.program.model.address.Address, threads: collections.abc.Sequence, kinds: collections.abc.Sequence, enabled: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]) -> TraceBreakpointLocation:
        """
        Add a breakpoint to the trace at a single address, starting at a given snap
        
        
        .. seealso::
        
            | :obj:`.addBreakpoint(String, Lifespan, AddressRange, Collection, Collection, boolean, String)`
        """

    @property
    def breakpointSpecificationsByPath(self) -> java.util.Collection[TraceBreakpointSpec]:
        ...

    @property
    def allBreakpointSpecifications(self) -> java.util.Collection[TraceBreakpointSpec]:
        ...

    @property
    def allBreakpointLocations(self) -> java.util.Collection[TraceBreakpointLocation]:
        ...

    @property
    def breakpointLocationsByPath(self) -> java.util.Collection[TraceBreakpointLocation]:
        ...


class TraceBreakpointCommon(ghidra.trace.model.TraceUniqueObject, ghidra.trace.model.target.iface.TraceObjectInterface):

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Delete this breakpoint from the trace
        """

    def getComment(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the comment on this breakpoint
        
        :param jpype.JLong or int snap: the snap
        :return: the comment, possibly ``null``
        :rtype: str
        """

    def getName(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the "short name" of this breakpoint
         
         
        
        This defaults to the "full name," but can be modified via :meth:`setName(long, String) <.setName>`
        
        :param jpype.JLong or int snap: the snap
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Get the "full name" of this breakpoint
         
         
        
        This is a name unique to this breakpoint, which may not be suitable for display on the
        screen.
        
        :return: the path
        :rtype: str
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this breakpoint
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isAlive(self, span: ghidra.trace.model.Lifespan) -> bool:
        """
        Check if the breakpoint is present for any of the given span
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: true if its life intersects the span
        :rtype: bool
        """

    def isEnabled(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check whether this breakpoint is enabled or disabled at the given snap
        
        :param jpype.JLong or int snap: the snap
        :return: true if enabled, false if disabled
        :rtype: bool
        """

    def isValid(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the breakpoint is present at the given snapshot
         
         
        
        In object mode, a breakpoint's life may be disjoint, so checking if the snap occurs between
        creation and destruction is not quite sufficient. This method encapsulates validity. In
        object mode, it checks that the breakpoint object has a canonical parent at the given
        snapshot. In table mode, it checks that the lifespan contains the snap.
        
        :param jpype.JLong or int snap: the snapshot key
        :return: true if valid, false if not
        :rtype: bool
        """

    def remove(self, snap: typing.Union[jpype.JLong, int]):
        """
        Remove this breakpoint from the given snap on
        
        :param jpype.JLong or int snap: the snap
        """

    @typing.overload
    def setComment(self, lifespan: ghidra.trace.model.Lifespan, comment: typing.Union[java.lang.String, str]):
        """
        Set a comment on this breakpoint
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str comment: the comment, possibly ``null``
        """

    @typing.overload
    def setComment(self, snap: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str]):
        """
        Set a comment on this breakpoint
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str comment: the comment, possibly ``null``
        """

    @typing.overload
    def setEnabled(self, lifespan: ghidra.trace.model.Lifespan, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this breakpoint was enabled or disabled
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param jpype.JBoolean or bool enabled: true if enabled, false if disabled
        """

    @typing.overload
    def setEnabled(self, snap: typing.Union[jpype.JLong, int], enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this breakpoint was enabled or disabled
        
        :param jpype.JLong or int snap: the first effective snap
        :param jpype.JBoolean or bool enabled: true if enabled, false if disabled
        """

    @typing.overload
    def setName(self, lifespan: ghidra.trace.model.Lifespan, name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this breakpoint
         
         
        
        This should be a name suitable for display on the screen
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str name: the new name
        """

    @typing.overload
    def setName(self, snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this breakpoint
         
         
        
        This should be a name suitable for display on the screen
        
        :param jpype.JLong or int snap: the first effective snap
        :param java.lang.String or str name: the new name
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def alive(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...


class TraceBreakpointLocation(TraceBreakpointCommon):

    class_: typing.ClassVar[java.lang.Class]
    KEY_RANGE: typing.Final = "_range"
    KEY_EMU_ENABLED: typing.Final = "_emu_enabled"
    KEY_EMU_SLEIGH: typing.Final = "_emu_sleigh"

    def getEmuSleigh(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the Sleigh source that replaces the breakpointed instruction in emulation
        
        :param jpype.JLong or int snap: the snap
        :return: the Sleigh source
        :rtype: str
        """

    def getKinds(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Set[TraceBreakpointKind]:
        """
        See :meth:`TraceBreakpointSpec.getKinds(long) <TraceBreakpointSpec.getKinds>`
        
        :param jpype.JLong or int snap: the snap
        :return: the kinds
        :rtype: java.util.Set[TraceBreakpointKind]
        """

    def getLength(self, snap: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the length of this breakpoint, usually 1
        
        :param jpype.JLong or int snap: the snap
        :return: the length
        :rtype: int
        """

    def getMaxAddress(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the maximum address in this breakpoint's range
        
        :param jpype.JLong or int snap: the snap
        :return: the maximum address
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.getRange(long)`
        """

    def getMinAddress(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the minimum address in this breakpoint's range
        
        :param jpype.JLong or int snap: the snap
        :return: the minimum address
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`.getRange(long)`
        """

    def getRange(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressRange:
        """
        Get the range covered by this breakpoint location
         
         
        
        Most often, esp. for execution breakpoints, this is a single address.
        
        :param jpype.JLong or int snap: the snap
        :return: the range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getSpecification(self) -> TraceBreakpointSpec:
        """
        Get the specification that caused this location to exist
        
        :return: the specification
        :rtype: TraceBreakpointSpec
        """

    def getThreads(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Set[ghidra.trace.model.thread.TraceThread]:
        """
        Get the set of threads to which this breakpoint's application is limited
         
         
        
        Note, an empty set here implies all contemporary live threads, i.e., the process.
        
        :param jpype.JLong or int snap: the snap
        :return: the (possibly empty) set of affected threads
        :rtype: java.util.Set[ghidra.trace.model.thread.TraceThread]
        """

    def isEmuEnabled(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check whether this breakpoint is enabled or disabled for emulation at the given snap
        
        :param jpype.JLong or int snap: the snap
        :return: true if enabled, false if disabled
        :rtype: bool
        """

    @typing.overload
    def setEmuEnabled(self, lifespan: ghidra.trace.model.Lifespan, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this breakpoint is enabled or disabled for emulation
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param jpype.JBoolean or bool enabled: true if enabled, false if disabled
        """

    @typing.overload
    def setEmuEnabled(self, snap: typing.Union[jpype.JLong, int], enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this breakpoint is enabled or disabled for emulation
        
        :param jpype.JLong or int snap: the snap
        :param jpype.JBoolean or bool enabled: true if enabled, false if disabled
        """

    @typing.overload
    def setEmuSleigh(self, lifespan: ghidra.trace.model.Lifespan, sleigh: typing.Union[java.lang.String, str]):
        """
        As in :meth:`setEmuSleigh(long, String) <.setEmuSleigh>`, but for a specific lifespan
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str sleigh: the Sleigh source
        """

    @typing.overload
    def setEmuSleigh(self, snap: typing.Union[jpype.JLong, int], sleigh: typing.Union[java.lang.String, str]):
        """
        Set Sleigh source to replace the breakpointed instruction in emulation
         
         
        
        The default is simply:
         
        
         
         
        :meth:`emu_swi() <PcodeEmulationLibrary.emu_swi>`;
        :meth:`emu_exec_decoded() <PcodeEmulationLibrary.emu_exec_decoded>`;
         
         
        
        That is effectively a non-conditional breakpoint followed by execution of the actual
        instruction. Modifying this allows clients to create conditional breakpoints or simply
        override or inject additional logic into an emulated target.
         
         
        
        **NOTE:** This currently has no effect on access breakpoints, but only execution
        breakpoints.
         
         
        
        If the specified source fails to compile during emulator set-up, this will fall back to
        :meth:`PcodeEmulationLibrary.emu_swi() <PcodeEmulationLibrary.emu_swi>`
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str sleigh: the Sleigh source
        
        .. seealso::
        
            | :obj:`SleighUtils.UNCONDITIONAL_BREAK`
        """

    def setRange(self, lifespan: ghidra.trace.model.Lifespan, range: ghidra.program.model.address.AddressRange):
        """
        Set the range covered by this breakpoint location
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param ghidra.program.model.address.AddressRange range: the span of addresses
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def emuSleigh(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def threads(self) -> java.util.Set[ghidra.trace.model.thread.TraceThread]:
        ...

    @property
    def specification(self) -> TraceBreakpointSpec:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def emuEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def kinds(self) -> java.util.Set[TraceBreakpointKind]:
        ...


class TraceBreakpointSpec(TraceBreakpointCommon):
    """
    The specification of a breakpoint applied to a target object
     
     
    
    Note that a single specification could result in several locations, or no locations at all. For
    example, a breakpoint placed on a function within a module which has not been loaded ("pending"
    in GDB's nomenclature), will not have any location. On the other hand, a breakpoint expressed by
    line number in a C++ template or a C macro could resolve to many addresses. The children of this
    object include the resolved :obj:`TraceBreakpointLocation`s. If the debugger does not share this
    same concept, then its breakpoints should implement both the specification and the location; the
    specification need not have any children.
     
     
    
    This object extends :obj:`TraceTogglable` for a transitional period only. Implementations
    whose breakpoint specifications can be toggled should declare this interface explicitly. When the
    specification is user togglable, toggling it should effectively toggle all locations -- whether
    or not the locations are user togglable.
     
     
    
    NOTE: When enumerating trace breakpoints, use the locations, not the specifications.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_EXPRESSION: typing.Final = "_expression"
    KEY_KINDS: typing.Final = "_kinds"
    KEY_AS_BPT: typing.Final = "_bpt"

    def getExpression(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the expression used to specify this breakpoint.
        
        :param jpype.JLong or int snap: the snap
        :return: the expression
        :rtype: str
        """

    def getKinds(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Set[TraceBreakpointKind]:
        """
        Get the kinds included in this breakpoint
         
         
        
        For example, an "access breakpoint" or "access watchpoint," depending on terminology, would
        include both :obj:`TraceBreakpointKind.READ` and :obj:`TraceBreakpointKind.WRITE`.
        
        :param jpype.JLong or int snap: the snap
        :return: the set of kinds
        :rtype: java.util.Set[TraceBreakpointKind]
        """

    def getLocations(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceBreakpointLocation]:
        """
        Get the locations for this breakpoint
        
        :param jpype.JLong or int snap: the snap
        :return: the locations
        :rtype: java.util.Collection[TraceBreakpointLocation]
        """

    @typing.overload
    def setKinds(self, lifespan: ghidra.trace.model.Lifespan, kinds: collections.abc.Sequence):
        """
        Set the kinds included in this breakpoint
         
         
        
        See :meth:`getKinds(long) <.getKinds>`. Note that it is unusual for a breakpoint to change kinds during
        its life. Nevertheless, in the course of recording a trace, it may happen, or at least appear
        to happen.
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param collections.abc.Sequence kinds: the set of kinds
        """

    @typing.overload
    def setKinds(self, snap: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence):
        """
        Set the kinds included in this breakpoint
         
         
        
        See :meth:`getKinds(long) <.getKinds>`. Note that it is unusual for a breakpoint to change kinds during
        its life. Nevertheless, in the course of recording a trace, it may happen, or at least appear
        to happen.
        
        :param jpype.JLong or int snap: the snap
        :param collections.abc.Sequence kinds: the set of kinds
        """

    @property
    def expression(self) -> java.lang.String:
        ...

    @property
    def locations(self) -> java.util.Collection[TraceBreakpointLocation]:
        ...

    @property
    def kinds(self) -> java.util.Set[TraceBreakpointKind]:
        ...


class TraceBreakpointKind(java.lang.Enum[TraceBreakpointKind]):
    """
    The kind of breakpoint
     
     
    
    This identifies the sort of access that would trap execution
     
     
    
    TODO: This is identical to ``TargetBreakpointKind`` (not in the classpath here). Is there a
    common place we could factor both? Should we? CAUTION: Encoding in a trace database depends on
    this enum's ``bits`` field, so we must take care not to introduce a dependency that would
    open us up to database breaks if the common enum changes.
    """

    class TraceBreakpointKindSet(org.apache.commons.collections4.set.AbstractSetDecorator[TraceBreakpointKind]):

        class_: typing.ClassVar[java.lang.Class]
        SW_EXECUTE: typing.Final[TraceBreakpointKind.TraceBreakpointKindSet]
        HW_EXECUTE: typing.Final[TraceBreakpointKind.TraceBreakpointKindSet]
        READ: typing.Final[TraceBreakpointKind.TraceBreakpointKindSet]
        WRITE: typing.Final[TraceBreakpointKind.TraceBreakpointKindSet]
        ACCESS: typing.Final[TraceBreakpointKind.TraceBreakpointKindSet]

        def __init__(self, set: java.util.Set[TraceBreakpointKind]):
            ...

        @staticmethod
        def copyOf(kinds: collections.abc.Sequence) -> TraceBreakpointKind.TraceBreakpointKindSet:
            ...

        @staticmethod
        def decode(encoded: typing.Union[java.lang.String, str], strict: typing.Union[jpype.JBoolean, bool]) -> TraceBreakpointKind.TraceBreakpointKindSet:
            """
            Convert a comma-separated list of kind names to a set of kinds.
            
            :param java.lang.String or str encoded: the encoded list
            :param jpype.JBoolean or bool strict: true to report unrecognized kinds, false to ignore
            :return: the decoded set
            :rtype: TraceBreakpointKind.TraceBreakpointKindSet
            """

        @staticmethod
        def encode(col: collections.abc.Sequence) -> str:
            """
            Convert a set (or collection) of kinds to a comma-separated list of names.
             
            The list is always encoded in order of the declaration of kinds (enum order).
            
            :param collections.abc.Sequence col: the set
            :return: the encoded list
            :rtype: str
            """

        @staticmethod
        def of(*kinds: TraceBreakpointKind) -> TraceBreakpointKind.TraceBreakpointKindSet:
            ...


    class_: typing.ClassVar[java.lang.Class]
    READ: typing.Final[TraceBreakpointKind]
    WRITE: typing.Final[TraceBreakpointKind]
    HW_EXECUTE: typing.Final[TraceBreakpointKind]
    SW_EXECUTE: typing.Final[TraceBreakpointKind]
    COUNT: typing.Final[jpype.JInt]

    def getBits(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TraceBreakpointKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[TraceBreakpointKind]:
        ...

    @property
    def bits(self) -> jpype.JByte:
        ...



__all__ = ["TraceBreakpointManager", "TraceBreakpointCommon", "TraceBreakpointLocation", "TraceBreakpointSpec", "TraceBreakpointKind"]
